pub const ZigGotSection = struct {
    entries: std.ArrayListUnmanaged(Symbol.Index) = .{},
    dirty: bool = false,

    pub const Index = u32;

    pub fn deinit(zig_got: *ZigGotSection, allocator: Allocator) void {
        zig_got.entries.deinit(allocator);
    }

    fn allocate_entry(zig_got: *ZigGotSection, allocator: Allocator) !Index {
        try zig_got.entries.ensure_unused_capacity(allocator, 1);
        // TODO add free list
        const index = @as(Index, @int_cast(zig_got.entries.items.len));
        _ = zig_got.entries.add_one_assume_capacity();
        zig_got.dirty = true;
        return index;
    }

    pub fn add_symbol(zig_got: *ZigGotSection, sym_index: Symbol.Index, macho_file: *MachO) !Index {
        const comp = macho_file.base.comp;
        const gpa = comp.gpa;
        const index = try zig_got.allocate_entry(gpa);
        const entry = &zig_got.entries.items[index];
        entry.* = sym_index;
        const symbol = macho_file.get_symbol(sym_index);
        assert(symbol.flags.needs_zig_got);
        symbol.flags.has_zig_got = true;
        try symbol.add_extra(.{ .zig_got = index }, macho_file);
        return index;
    }

    pub fn entry_offset(zig_got: ZigGotSection, index: Index, macho_file: *MachO) u64 {
        _ = zig_got;
        const sect = macho_file.sections.items(.header)[macho_file.zig_got_sect_index.?];
        return sect.offset + @size_of(u64) * index;
    }

    pub fn entry_address(zig_got: ZigGotSection, index: Index, macho_file: *MachO) u64 {
        _ = zig_got;
        const sect = macho_file.sections.items(.header)[macho_file.zig_got_sect_index.?];
        return sect.addr + @size_of(u64) * index;
    }

    pub fn size(zig_got: ZigGotSection, macho_file: *MachO) usize {
        _ = macho_file;
        return @size_of(u64) * zig_got.entries.items.len;
    }

    pub fn write_one(zig_got: *ZigGotSection, macho_file: *MachO, index: Index) !void {
        if (zig_got.dirty) {
            const needed_size = zig_got.size(macho_file);
            try macho_file.grow_section(macho_file.zig_got_sect_index.?, needed_size);
            zig_got.dirty = false;
        }
        const off = zig_got.entry_offset(index, macho_file);
        const entry = zig_got.entries.items[index];
        const value = macho_file.get_symbol(entry).get_address(.{ .stubs = false }, macho_file);

        var buf: [8]u8 = undefined;
        std.mem.write_int(u64, &buf, value, .little);
        try macho_file.base.file.?.pwrite_all(&buf, off);
    }

    pub fn write_all(zig_got: ZigGotSection, macho_file: *MachO, writer: anytype) !void {
        for (zig_got.entries.items) |entry| {
            const symbol = macho_file.get_symbol(entry);
            const value = symbol.address(.{ .stubs = false }, macho_file);
            try writer.write_int(u64, value, .little);
        }
    }

    pub fn add_dyld_relocs(zig_got: ZigGotSection, macho_file: *MachO) !void {
        const tracy = trace(@src());
        defer tracy.end();
        const gpa = macho_file.base.comp.gpa;
        const seg_id = macho_file.sections.items(.segment_id)[macho_file.zig_got_sect_index.?];
        const seg = macho_file.segments.items[seg_id];

        for (0..zig_got.entries.items.len) |idx| {
            const addr = zig_got.entry_address(@int_cast(idx), macho_file);
            try macho_file.rebase.entries.append(gpa, .{
                .offset = addr - seg.vmaddr,
                .segment_id = seg_id,
            });
        }
    }

    const FormatCtx = struct {
        zig_got: ZigGotSection,
        macho_file: *MachO,
    };

    pub fn fmt(zig_got: ZigGotSection, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{ .zig_got = zig_got, .macho_file = macho_file } };
    }

    pub fn format2(
        ctx: FormatCtx,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        try writer.write_all("__zig_got\n");
        for (ctx.zig_got.entries.items, 0..) |entry, index| {
            const symbol = ctx.macho_file.get_symbol(entry);
            try writer.print("  {d}@0x{x} => {d}@0x{x} ({s})\n", .{
                index,
                ctx.zig_got.entry_address(@int_cast(index), ctx.macho_file),
                entry,
                symbol.get_address(.{}, ctx.macho_file),
                symbol.get_name(ctx.macho_file),
            });
        }
    }
};

pub const GotSection = struct {
    symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

    pub const Index = u32;

    pub fn deinit(got: *GotSection, allocator: Allocator) void {
        got.symbols.deinit(allocator);
    }

    pub fn add_symbol(got: *GotSection, sym_index: Symbol.Index, macho_file: *MachO) !void {
        const gpa = macho_file.base.comp.gpa;
        const index = @as(Index, @int_cast(got.symbols.items.len));
        const entry = try got.symbols.add_one(gpa);
        entry.* = sym_index;
        const symbol = macho_file.get_symbol(sym_index);
        symbol.flags.has_got = true;
        try symbol.add_extra(.{ .got = index }, macho_file);
    }

    pub fn get_address(got: GotSection, index: Index, macho_file: *MachO) u64 {
        assert(index < got.symbols.items.len);
        const header = macho_file.sections.items(.header)[macho_file.got_sect_index.?];
        return header.addr + index * @size_of(u64);
    }

    pub fn size(got: GotSection) usize {
        return got.symbols.items.len * @size_of(u64);
    }

    pub fn add_dyld_relocs(got: GotSection, macho_file: *MachO) !void {
        const tracy = trace(@src());
        defer tracy.end();
        const gpa = macho_file.base.comp.gpa;
        const seg_id = macho_file.sections.items(.segment_id)[macho_file.got_sect_index.?];
        const seg = macho_file.segments.items[seg_id];

        for (got.symbols.items, 0..) |sym_index, idx| {
            const sym = macho_file.get_symbol(sym_index);
            const addr = got.get_address(@int_cast(idx), macho_file);
            const entry = bind.Entry{
                .target = sym_index,
                .offset = addr - seg.vmaddr,
                .segment_id = seg_id,
                .addend = 0,
            };
            if (sym.flags.import) {
                try macho_file.bind.entries.append(gpa, entry);
                if (sym.flags.weak) {
                    try macho_file.weak_bind.entries.append(gpa, entry);
                }
            } else {
                try macho_file.rebase.entries.append(gpa, .{
                    .offset = addr - seg.vmaddr,
                    .segment_id = seg_id,
                });
                if (sym.flags.weak) {
                    try macho_file.weak_bind.entries.append(gpa, entry);
                } else if (sym.flags.interposable) {
                    try macho_file.bind.entries.append(gpa, entry);
                }
            }
        }
    }

    pub fn write(got: GotSection, macho_file: *MachO, writer: anytype) !void {
        const tracy = trace(@src());
        defer tracy.end();
        for (got.symbols.items) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            const value = if (sym.flags.import) @as(u64, 0) else sym.get_address(.{}, macho_file);
            try writer.write_int(u64, value, .little);
        }
    }

    const FormatCtx = struct {
        got: GotSection,
        macho_file: *MachO,
    };

    pub fn fmt(got: GotSection, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{ .got = got, .macho_file = macho_file } };
    }

    pub fn format2(
        ctx: FormatCtx,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        for (ctx.got.symbols.items, 0..) |entry, i| {
            const symbol = ctx.macho_file.get_symbol(entry);
            try writer.print("  {d}@0x{x} => {d}@0x{x} ({s})\n", .{
                i,
                symbol.get_got_address(ctx.macho_file),
                entry,
                symbol.get_address(.{}, ctx.macho_file),
                symbol.get_name(ctx.macho_file),
            });
        }
    }
};

pub const StubsSection = struct {
    symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

    pub const Index = u32;

    pub fn deinit(stubs: *StubsSection, allocator: Allocator) void {
        stubs.symbols.deinit(allocator);
    }

    pub fn add_symbol(stubs: *StubsSection, sym_index: Symbol.Index, macho_file: *MachO) !void {
        const gpa = macho_file.base.comp.gpa;
        const index = @as(Index, @int_cast(stubs.symbols.items.len));
        const entry = try stubs.symbols.add_one(gpa);
        entry.* = sym_index;
        const symbol = macho_file.get_symbol(sym_index);
        try symbol.add_extra(.{ .stubs = index }, macho_file);
    }

    pub fn get_address(stubs: StubsSection, index: Index, macho_file: *MachO) u64 {
        assert(index < stubs.symbols.items.len);
        const header = macho_file.sections.items(.header)[macho_file.stubs_sect_index.?];
        return header.addr + index * header.reserved2;
    }

    pub fn size(stubs: StubsSection, macho_file: *MachO) usize {
        const header = macho_file.sections.items(.header)[macho_file.stubs_sect_index.?];
        return stubs.symbols.items.len * header.reserved2;
    }

    pub fn write(stubs: StubsSection, macho_file: *MachO, writer: anytype) !void {
        const tracy = trace(@src());
        defer tracy.end();
        const cpu_arch = macho_file.get_target().cpu.arch;
        const laptr_sect = macho_file.sections.items(.header)[macho_file.la_symbol_ptr_sect_index.?];

        for (stubs.symbols.items, 0..) |sym_index, idx| {
            const sym = macho_file.get_symbol(sym_index);
            const source = sym.get_address(.{ .stubs = true }, macho_file);
            const target = laptr_sect.addr + idx * @size_of(u64);
            switch (cpu_arch) {
                .x86_64 => {
                    try writer.write_all(&.{ 0xff, 0x25 });
                    try writer.write_int(i32, @int_cast(target - source - 2 - 4), .little);
                },
                .aarch64 => {
                    // TODO relax if possible
                    const pages = try aarch64.calc_number_of_pages(@int_cast(source), @int_cast(target));
                    try writer.write_int(u32, aarch64.Instruction.adrp(.x16, pages).to_u32(), .little);
                    const off = try math.div_exact(u12, @truncate(target), 8);
                    try writer.write_int(
                        u32,
                        aarch64.Instruction.ldr(.x16, .x16, aarch64.Instruction.LoadStoreOffset.imm(off)).to_u32(),
                        .little,
                    );
                    try writer.write_int(u32, aarch64.Instruction.br(.x16).to_u32(), .little);
                },
                else => unreachable,
            }
        }
    }

    const FormatCtx = struct {
        stubs: StubsSection,
        macho_file: *MachO,
    };

    pub fn fmt(stubs: StubsSection, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{ .stubs = stubs, .macho_file = macho_file } };
    }

    pub fn format2(
        ctx: FormatCtx,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        for (ctx.stubs.symbols.items, 0..) |entry, i| {
            const symbol = ctx.macho_file.get_symbol(entry);
            try writer.print("  {d}@0x{x} => {d}@0x{x} ({s})\n", .{
                i,
                symbol.get_stubs_address(ctx.macho_file),
                entry,
                symbol.get_address(.{}, ctx.macho_file),
                symbol.get_name(ctx.macho_file),
            });
        }
    }
};

pub const StubsHelperSection = struct {
    pub inline fn preamble_size(cpu_arch: std.Target.Cpu.Arch) usize {
        return switch (cpu_arch) {
            .x86_64 => 16,
            .aarch64 => 6 * @size_of(u32),
            else => 0,
        };
    }

    pub inline fn entry_size(cpu_arch: std.Target.Cpu.Arch) usize {
        return switch (cpu_arch) {
            .x86_64 => 10,
            .aarch64 => 3 * @size_of(u32),
            else => 0,
        };
    }

    pub fn size(stubs_helper: StubsHelperSection, macho_file: *MachO) usize {
        const tracy = trace(@src());
        defer tracy.end();
        _ = stubs_helper;
        const cpu_arch = macho_file.get_target().cpu.arch;
        var s: usize = preamble_size(cpu_arch);
        for (macho_file.stubs.symbols.items) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            if (sym.flags.weak) continue;
            s += entry_size(cpu_arch);
        }
        return s;
    }

    pub fn write(stubs_helper: StubsHelperSection, macho_file: *MachO, writer: anytype) !void {
        const tracy = trace(@src());
        defer tracy.end();

        try stubs_helper.write_preamble(macho_file, writer);

        const cpu_arch = macho_file.get_target().cpu.arch;
        const sect = macho_file.sections.items(.header)[macho_file.stubs_helper_sect_index.?];
        const preamble_size = preamble_size(cpu_arch);
        const entry_size = entry_size(cpu_arch);

        var idx: usize = 0;
        for (macho_file.stubs.symbols.items) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            if (sym.flags.weak) continue;
            const offset = macho_file.lazy_bind.offsets.items[idx];
            const source: i64 = @int_cast(sect.addr + preamble_size + entry_size * idx);
            const target: i64 = @int_cast(sect.addr);
            switch (cpu_arch) {
                .x86_64 => {
                    try writer.write_byte(0x68);
                    try writer.write_int(u32, offset, .little);
                    try writer.write_byte(0xe9);
                    try writer.write_int(i32, @int_cast(target - source - 6 - 4), .little);
                },
                .aarch64 => {
                    const literal = blk: {
                        const div_res = try std.math.div_exact(u64, entry_size - @size_of(u32), 4);
                        break :blk std.math.cast(u18, div_res) orelse return error.Overflow;
                    };
                    try writer.write_int(u32, aarch64.Instruction.ldr_literal(
                        .w16,
                        literal,
                    ).to_u32(), .little);
                    const disp = math.cast(i28, @as(i64, @int_cast(target)) - @as(i64, @int_cast(source + 4))) orelse
                        return error.Overflow;
                    try writer.write_int(u32, aarch64.Instruction.b(disp).to_u32(), .little);
                    try writer.write_all(&.{ 0x0, 0x0, 0x0, 0x0 });
                },
                else => unreachable,
            }
            idx += 1;
        }
    }

    fn write_preamble(stubs_helper: StubsHelperSection, macho_file: *MachO, writer: anytype) !void {
        _ = stubs_helper;
        const cpu_arch = macho_file.get_target().cpu.arch;
        const sect = macho_file.sections.items(.header)[macho_file.stubs_helper_sect_index.?];
        const dyld_private_addr = target: {
            const sym = macho_file.get_symbol(macho_file.dyld_private_index.?);
            break :target sym.get_address(.{}, macho_file);
        };
        const dyld_stub_binder_addr = target: {
            const sym = macho_file.get_symbol(macho_file.dyld_stub_binder_index.?);
            break :target sym.get_got_address(macho_file);
        };
        switch (cpu_arch) {
            .x86_64 => {
                try writer.write_all(&.{ 0x4c, 0x8d, 0x1d });
                try writer.write_int(i32, @int_cast(dyld_private_addr - sect.addr - 3 - 4), .little);
                try writer.write_all(&.{ 0x41, 0x53, 0xff, 0x25 });
                try writer.write_int(i32, @int_cast(dyld_stub_binder_addr - sect.addr - 11 - 4), .little);
                try writer.write_byte(0x90);
            },
            .aarch64 => {
                {
                    // TODO relax if possible
                    const pages = try aarch64.calc_number_of_pages(@int_cast(sect.addr), @int_cast(dyld_private_addr));
                    try writer.write_int(u32, aarch64.Instruction.adrp(.x17, pages).to_u32(), .little);
                    const off: u12 = @truncate(dyld_private_addr);
                    try writer.write_int(u32, aarch64.Instruction.add(.x17, .x17, off, false).to_u32(), .little);
                }
                try writer.write_int(u32, aarch64.Instruction.stp(
                    .x16,
                    .x17,
                    aarch64.Register.sp,
                    aarch64.Instruction.LoadStorePairOffset.pre_index(-16),
                ).to_u32(), .little);
                {
                    // TODO relax if possible
                    const pages = try aarch64.calc_number_of_pages(@int_cast(sect.addr + 12), @int_cast(dyld_stub_binder_addr));
                    try writer.write_int(u32, aarch64.Instruction.adrp(.x16, pages).to_u32(), .little);
                    const off = try math.div_exact(u12, @truncate(dyld_stub_binder_addr), 8);
                    try writer.write_int(u32, aarch64.Instruction.ldr(
                        .x16,
                        .x16,
                        aarch64.Instruction.LoadStoreOffset.imm(off),
                    ).to_u32(), .little);
                }
                try writer.write_int(u32, aarch64.Instruction.br(.x16).to_u32(), .little);
            },
            else => unreachable,
        }
    }
};

pub const LaSymbolPtrSection = struct {
    pub fn size(laptr: LaSymbolPtrSection, macho_file: *MachO) usize {
        _ = laptr;
        return macho_file.stubs.symbols.items.len * @size_of(u64);
    }

    pub fn add_dyld_relocs(laptr: LaSymbolPtrSection, macho_file: *MachO) !void {
        const tracy = trace(@src());
        defer tracy.end();
        _ = laptr;
        const gpa = macho_file.base.comp.gpa;

        const sect = macho_file.sections.items(.header)[macho_file.la_symbol_ptr_sect_index.?];
        const seg_id = macho_file.sections.items(.segment_id)[macho_file.la_symbol_ptr_sect_index.?];
        const seg = macho_file.segments.items[seg_id];

        for (macho_file.stubs.symbols.items, 0..) |sym_index, idx| {
            const sym = macho_file.get_symbol(sym_index);
            const addr = sect.addr + idx * @size_of(u64);
            const rebase_entry = Rebase.Entry{
                .offset = addr - seg.vmaddr,
                .segment_id = seg_id,
            };
            const bind_entry = bind.Entry{
                .target = sym_index,
                .offset = addr - seg.vmaddr,
                .segment_id = seg_id,
                .addend = 0,
            };
            if (sym.flags.import) {
                if (sym.flags.weak) {
                    try macho_file.bind.entries.append(gpa, bind_entry);
                    try macho_file.weak_bind.entries.append(gpa, bind_entry);
                } else {
                    try macho_file.lazy_bind.entries.append(gpa, bind_entry);
                    try macho_file.rebase.entries.append(gpa, rebase_entry);
                }
            } else {
                if (sym.flags.weak) {
                    try macho_file.rebase.entries.append(gpa, rebase_entry);
                    try macho_file.weak_bind.entries.append(gpa, bind_entry);
                } else if (sym.flags.interposable) {
                    try macho_file.lazy_bind.entries.append(gpa, bind_entry);
                    try macho_file.rebase.entries.append(gpa, rebase_entry);
                }
            }
        }
    }

    pub fn write(laptr: LaSymbolPtrSection, macho_file: *MachO, writer: anytype) !void {
        const tracy = trace(@src());
        defer tracy.end();
        _ = laptr;
        const cpu_arch = macho_file.get_target().cpu.arch;
        const sect = macho_file.sections.items(.header)[macho_file.stubs_helper_sect_index.?];
        var stub_helper_idx: u32 = 0;
        for (macho_file.stubs.symbols.items) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            if (sym.flags.weak) {
                const value = sym.get_address(.{ .stubs = false }, macho_file);
                try writer.write_int(u64, @int_cast(value), .little);
            } else {
                const value = sect.addr + StubsHelperSection.preamble_size(cpu_arch) +
                    StubsHelperSection.entry_size(cpu_arch) * stub_helper_idx;
                stub_helper_idx += 1;
                try writer.write_int(u64, @int_cast(value), .little);
            }
        }
    }
};

pub const TlvPtrSection = struct {
    symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

    pub const Index = u32;

    pub fn deinit(tlv: *TlvPtrSection, allocator: Allocator) void {
        tlv.symbols.deinit(allocator);
    }

    pub fn add_symbol(tlv: *TlvPtrSection, sym_index: Symbol.Index, macho_file: *MachO) !void {
        const gpa = macho_file.base.comp.gpa;
        const index = @as(Index, @int_cast(tlv.symbols.items.len));
        const entry = try tlv.symbols.add_one(gpa);
        entry.* = sym_index;
        const symbol = macho_file.get_symbol(sym_index);
        try symbol.add_extra(.{ .tlv_ptr = index }, macho_file);
    }

    pub fn get_address(tlv: TlvPtrSection, index: Index, macho_file: *MachO) u64 {
        assert(index < tlv.symbols.items.len);
        const header = macho_file.sections.items(.header)[macho_file.tlv_ptr_sect_index.?];
        return header.addr + index * @size_of(u64);
    }

    pub fn size(tlv: TlvPtrSection) usize {
        return tlv.symbols.items.len * @size_of(u64);
    }

    pub fn add_dyld_relocs(tlv: TlvPtrSection, macho_file: *MachO) !void {
        const tracy = trace(@src());
        defer tracy.end();
        const gpa = macho_file.base.comp.gpa;
        const seg_id = macho_file.sections.items(.segment_id)[macho_file.tlv_ptr_sect_index.?];
        const seg = macho_file.segments.items[seg_id];

        for (tlv.symbols.items, 0..) |sym_index, idx| {
            const sym = macho_file.get_symbol(sym_index);
            const addr = tlv.get_address(@int_cast(idx), macho_file);
            const entry = bind.Entry{
                .target = sym_index,
                .offset = addr - seg.vmaddr,
                .segment_id = seg_id,
                .addend = 0,
            };
            if (sym.flags.import) {
                try macho_file.bind.entries.append(gpa, entry);
                if (sym.flags.weak) {
                    try macho_file.weak_bind.entries.append(gpa, entry);
                }
            } else {
                try macho_file.rebase.entries.append(gpa, .{
                    .offset = addr - seg.vmaddr,
                    .segment_id = seg_id,
                });
                if (sym.flags.weak) {
                    try macho_file.weak_bind.entries.append(gpa, entry);
                } else if (sym.flags.interposable) {
                    try macho_file.bind.entries.append(gpa, entry);
                }
            }
        }
    }

    pub fn write(tlv: TlvPtrSection, macho_file: *MachO, writer: anytype) !void {
        const tracy = trace(@src());
        defer tracy.end();

        for (tlv.symbols.items) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            if (sym.flags.import) {
                try writer.write_int(u64, 0, .little);
            } else {
                try writer.write_int(u64, sym.get_address(.{}, macho_file), .little);
            }
        }
    }

    const FormatCtx = struct {
        tlv: TlvPtrSection,
        macho_file: *MachO,
    };

    pub fn fmt(tlv: TlvPtrSection, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{ .tlv = tlv, .macho_file = macho_file } };
    }

    pub fn format2(
        ctx: FormatCtx,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        for (ctx.tlv.symbols.items, 0..) |entry, i| {
            const symbol = ctx.macho_file.get_symbol(entry);
            try writer.print("  {d}@0x{x} => {d}@0x{x} ({s})\n", .{
                i,
                symbol.get_tlv_ptr_address(ctx.macho_file),
                entry,
                symbol.get_address(.{}, ctx.macho_file),
                symbol.get_name(ctx.macho_file),
            });
        }
    }
};

pub const ObjcStubsSection = struct {
    symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

    pub fn deinit(objc: *ObjcStubsSection, allocator: Allocator) void {
        objc.symbols.deinit(allocator);
    }

    pub fn entry_size(cpu_arch: std.Target.Cpu.Arch) u8 {
        return switch (cpu_arch) {
            .x86_64 => 13,
            .aarch64 => 8 * @size_of(u32),
            else => unreachable,
        };
    }

    pub fn add_symbol(objc: *ObjcStubsSection, sym_index: Symbol.Index, macho_file: *MachO) !void {
        const gpa = macho_file.base.comp.gpa;
        const index = @as(Index, @int_cast(objc.symbols.items.len));
        const entry = try objc.symbols.add_one(gpa);
        entry.* = sym_index;
        const symbol = macho_file.get_symbol(sym_index);
        try symbol.add_extra(.{ .objc_stubs = index }, macho_file);
    }

    pub fn get_address(objc: ObjcStubsSection, index: Index, macho_file: *MachO) u64 {
        assert(index < objc.symbols.items.len);
        const header = macho_file.sections.items(.header)[macho_file.objc_stubs_sect_index.?];
        return header.addr + index * entry_size(macho_file.get_target().cpu.arch);
    }

    pub fn size(objc: ObjcStubsSection, macho_file: *MachO) usize {
        return objc.symbols.items.len * entry_size(macho_file.get_target().cpu.arch);
    }

    pub fn write(objc: ObjcStubsSection, macho_file: *MachO, writer: anytype) !void {
        const tracy = trace(@src());
        defer tracy.end();

        for (objc.symbols.items, 0..) |sym_index, idx| {
            const sym = macho_file.get_symbol(sym_index);
            const addr = objc.get_address(@int_cast(idx), macho_file);
            switch (macho_file.get_target().cpu.arch) {
                .x86_64 => {
                    try writer.write_all(&.{ 0x48, 0x8b, 0x35 });
                    {
                        const target = sym.get_objc_selrefs_address(macho_file);
                        const source = addr;
                        try writer.write_int(i32, @int_cast(target - source - 3 - 4), .little);
                    }
                    try writer.write_all(&.{ 0xff, 0x25 });
                    {
                        const target_sym = macho_file.get_symbol(macho_file.objc_msg_send_index.?);
                        const target = target_sym.get_got_address(macho_file);
                        const source = addr + 7;
                        try writer.write_int(i32, @int_cast(target - source - 2 - 4), .little);
                    }
                },
                .aarch64 => {
                    {
                        const target = sym.get_objc_selrefs_address(macho_file);
                        const source = addr;
                        const pages = try aarch64.calc_number_of_pages(@int_cast(source), @int_cast(target));
                        try writer.write_int(u32, aarch64.Instruction.adrp(.x1, pages).to_u32(), .little);
                        const off = try math.div_exact(u12, @truncate(target), 8);
                        try writer.write_int(
                            u32,
                            aarch64.Instruction.ldr(.x1, .x1, aarch64.Instruction.LoadStoreOffset.imm(off)).to_u32(),
                            .little,
                        );
                    }
                    {
                        const target_sym = macho_file.get_symbol(macho_file.objc_msg_send_index.?);
                        const target = target_sym.get_got_address(macho_file);
                        const source = addr + 2 * @size_of(u32);
                        const pages = try aarch64.calc_number_of_pages(@int_cast(source), @int_cast(target));
                        try writer.write_int(u32, aarch64.Instruction.adrp(.x16, pages).to_u32(), .little);
                        const off = try math.div_exact(u12, @truncate(target), 8);
                        try writer.write_int(
                            u32,
                            aarch64.Instruction.ldr(.x16, .x16, aarch64.Instruction.LoadStoreOffset.imm(off)).to_u32(),
                            .little,
                        );
                    }
                    try writer.write_int(u32, aarch64.Instruction.br(.x16).to_u32(), .little);
                    try writer.write_int(u32, aarch64.Instruction.brk(1).to_u32(), .little);
                    try writer.write_int(u32, aarch64.Instruction.brk(1).to_u32(), .little);
                    try writer.write_int(u32, aarch64.Instruction.brk(1).to_u32(), .little);
                },
                else => unreachable,
            }
        }
    }

    const FormatCtx = struct {
        objc: ObjcStubsSection,
        macho_file: *MachO,
    };

    pub fn fmt(objc: ObjcStubsSection, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{ .objc = objc, .macho_file = macho_file } };
    }

    pub fn format2(
        ctx: FormatCtx,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        for (ctx.objc.symbols.items, 0..) |entry, i| {
            const symbol = ctx.macho_file.get_symbol(entry);
            try writer.print("  {d}@0x{x} => {d}@0x{x} ({s})\n", .{
                i,
                symbol.get_objc_stubs_address(ctx.macho_file),
                entry,
                symbol.get_address(.{}, ctx.macho_file),
                symbol.get_name(ctx.macho_file),
            });
        }
    }

    pub const Index = u32;
};

pub const Indsymtab = struct {
    pub inline fn nsyms(ind: Indsymtab, macho_file: *MachO) u32 {
        _ = ind;
        return @int_cast(macho_file.stubs.symbols.items.len * 2 + macho_file.got.symbols.items.len);
    }

    pub fn write(ind: Indsymtab, macho_file: *MachO, writer: anytype) !void {
        const tracy = trace(@src());
        defer tracy.end();

        _ = ind;

        for (macho_file.stubs.symbols.items) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            try writer.write_int(u32, sym.get_output_symtab_index(macho_file).?, .little);
        }

        for (macho_file.got.symbols.items) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            try writer.write_int(u32, sym.get_output_symtab_index(macho_file).?, .little);
        }

        for (macho_file.stubs.symbols.items) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            try writer.write_int(u32, sym.get_output_symtab_index(macho_file).?, .little);
        }
    }
};

pub const RebaseSection = Rebase;
pub const BindSection = bind.Bind;
pub const WeakBindSection = bind.WeakBind;
pub const LazyBindSection = bind.LazyBind;
pub const ExportTrieSection = Trie;

const aarch64 = @import("../aarch64.zig");
const assert = std.debug.assert;
const bind = @import("dyld_info/bind.zig");
const math = std.math;
const std = @import("std");
const trace = @import("../../tracy.zig").trace;

const Allocator = std.mem.Allocator;
const MachO = @import("../MachO.zig");
const Rebase = @import("dyld_info/Rebase.zig");
const Symbol = @import("Symbol.zig");
const Trie = @import("dyld_info/Trie.zig");
