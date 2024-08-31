pub const Cie = struct {
    /// Includes 4byte size cell.
    offset: u32,
    out_offset: u32 = 0,
    size: u32,
    lsda_size: ?enum { p32, p64 } = null,
    personality: ?Personality = null,
    file: File.Index = 0,
    alive: bool = false,

    pub fn parse(cie: *Cie, macho_file: *MachO) !void {
        const tracy = trace(@src());
        defer tracy.end();

        const data = cie.get_data(macho_file);
        const aug = std.mem.slice_to(@as([*:0]const u8, @ptr_cast(data.ptr + 9)), 0);

        if (aug[0] != 'z') return; // TODO should we error out?

        var stream = std.io.fixed_buffer_stream(data[9 + aug.len + 1 ..]);
        var creader = std.io.counting_reader(stream.reader());
        const reader = creader.reader();

        _ = try leb.read_uleb128(u64, reader); // code alignment factor
        _ = try leb.read_uleb128(u64, reader); // data alignment factor
        _ = try leb.read_uleb128(u64, reader); // return address register
        _ = try leb.read_uleb128(u64, reader); // augmentation data length

        for (aug[1..]) |ch| switch (ch) {
            'R' => {
                const enc = try reader.read_byte();
                if (enc & 0xf != EH_PE.absptr or enc & EH_PE.pcrel == 0) {
                    @panic("unexpected pointer encoding"); // TODO error
                }
            },
            'P' => {
                const enc = try reader.read_byte();
                if (enc != EH_PE.pcrel | EH_PE.indirect | EH_PE.sdata4) {
                    @panic("unexpected personality pointer encoding"); // TODO error
                }
                _ = try reader.read_int(u32, .little); // personality pointer
            },
            'L' => {
                const enc = try reader.read_byte();
                switch (enc & 0xf) {
                    EH_PE.sdata4 => cie.lsda_size = .p32,
                    EH_PE.absptr => cie.lsda_size = .p64,
                    else => unreachable, // TODO error
                }
            },
            else => @panic("unexpected augmentation string"), // TODO error
        };
    }

    pub inline fn get_size(cie: Cie) u32 {
        return cie.size + 4;
    }

    pub fn get_object(cie: Cie, macho_file: *MachO) *Object {
        const file = macho_file.get_file(cie.file).?;
        return file.object;
    }

    pub fn get_data(cie: Cie, macho_file: *MachO) []const u8 {
        const object = cie.get_object(macho_file);
        return object.eh_frame_data.items[cie.offset..][0..cie.get_size()];
    }

    pub fn get_personality(cie: Cie, macho_file: *MachO) ?*Symbol {
        const personality = cie.personality orelse return null;
        return macho_file.get_symbol(personality.index);
    }

    pub fn eql(cie: Cie, other: Cie, macho_file: *MachO) bool {
        if (!std.mem.eql(u8, cie.get_data(macho_file), other.get_data(macho_file))) return false;
        if (cie.personality != null and other.personality != null) {
            if (cie.personality.?.index != other.personality.?.index) return false;
        }
        if (cie.personality != null or other.personality != null) return false;
        return true;
    }

    pub fn format(
        cie: Cie,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = cie;
        _ = unused_fmt_string;
        _ = options;
        _ = writer;
        @compile_error("do not format CIEs directly");
    }

    pub fn fmt(cie: Cie, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{
            .cie = cie,
            .macho_file = macho_file,
        } };
    }

    const FormatContext = struct {
        cie: Cie,
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
        const cie = ctx.cie;
        try writer.print("@{x} : size({x})", .{
            cie.offset,
            cie.get_size(),
        });
        if (!cie.alive) try writer.write_all(" : [*]");
    }

    pub const Index = u32;

    pub const Personality = struct {
        index: Symbol.Index = 0,
        offset: u32 = 0,
    };
};

pub const Fde = struct {
    /// Includes 4byte size cell.
    offset: u32,
    out_offset: u32 = 0,
    size: u32,
    cie: Cie.Index,
    atom: Atom.Index = 0,
    atom_offset: u32 = 0,
    lsda: Atom.Index = 0,
    lsda_offset: u32 = 0,
    lsda_ptr_offset: u32 = 0,
    file: File.Index = 0,
    alive: bool = true,

    pub fn parse(fde: *Fde, macho_file: *MachO) !void {
        const tracy = trace(@src());
        defer tracy.end();

        const data = fde.get_data(macho_file);
        const object = fde.get_object(macho_file);
        const sect = object.sections.items(.header)[object.eh_frame_sect_index.?];

        // Parse target atom index
        const pc_begin = std.mem.read_int(i64, data[8..][0..8], .little);
        const taddr: u64 = @int_cast(@as(i64, @int_cast(sect.addr + fde.offset + 8)) + pc_begin);
        fde.atom = object.find_atom(taddr) orelse {
            try macho_file.report_parse_error2(object.index, "{s},{s}: 0x{x}: invalid function reference in FDE", .{
                sect.seg_name(), sect.sect_name(), fde.offset + 8,
            });
            return error.MalformedObject;
        };
        const atom = fde.get_atom(macho_file);
        fde.atom_offset = @int_cast(taddr - atom.get_input_address(macho_file));

        // Associate with a CIE
        const cie_ptr = std.mem.read_int(u32, data[4..8], .little);
        const cie_offset = fde.offset + 4 - cie_ptr;
        const cie_index = for (object.cies.items, 0..) |cie, cie_index| {
            if (cie.offset == cie_offset) break @as(Cie.Index, @int_cast(cie_index));
        } else null;
        if (cie_index) |cie| {
            fde.cie = cie;
        } else {
            try macho_file.report_parse_error2(object.index, "no matching CIE found for FDE at offset {x}", .{
                fde.offset,
            });
            return error.MalformedObject;
        }

        const cie = fde.get_cie(macho_file);

        // Parse LSDA atom index if any
        if (cie.lsda_size) |lsda_size| {
            var stream = std.io.fixed_buffer_stream(data[24..]);
            var creader = std.io.counting_reader(stream.reader());
            const reader = creader.reader();
            _ = try leb.read_uleb128(u64, reader); // augmentation length
            fde.lsda_ptr_offset = @int_cast(creader.bytes_read + 24);
            const lsda_ptr = switch (lsda_size) {
                .p32 => try reader.read_int(i32, .little),
                .p64 => try reader.read_int(i64, .little),
            };
            const lsda_addr: u64 = @int_cast(@as(i64, @int_cast(sect.addr + fde.offset + fde.lsda_ptr_offset)) + lsda_ptr);
            fde.lsda = object.find_atom(lsda_addr) orelse {
                try macho_file.report_parse_error2(object.index, "{s},{s}: 0x{x}: invalid LSDA reference in FDE", .{
                    sect.seg_name(), sect.sect_name(), fde.offset + fde.lsda_ptr_offset,
                });
                return error.MalformedObject;
            };
            const lsda_atom = fde.get_lsda_atom(macho_file).?;
            fde.lsda_offset = @int_cast(lsda_addr - lsda_atom.get_input_address(macho_file));
        }
    }

    pub inline fn get_size(fde: Fde) u32 {
        return fde.size + 4;
    }

    pub fn get_object(fde: Fde, macho_file: *MachO) *Object {
        const file = macho_file.get_file(fde.file).?;
        return file.object;
    }

    pub fn get_data(fde: Fde, macho_file: *MachO) []const u8 {
        const object = fde.get_object(macho_file);
        return object.eh_frame_data.items[fde.offset..][0..fde.get_size()];
    }

    pub fn get_cie(fde: Fde, macho_file: *MachO) *const Cie {
        const object = fde.get_object(macho_file);
        return &object.cies.items[fde.cie];
    }

    pub fn get_atom(fde: Fde, macho_file: *MachO) *Atom {
        return macho_file.get_atom(fde.atom).?;
    }

    pub fn get_lsda_atom(fde: Fde, macho_file: *MachO) ?*Atom {
        return macho_file.get_atom(fde.lsda);
    }

    pub fn format(
        fde: Fde,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fde;
        _ = unused_fmt_string;
        _ = options;
        _ = writer;
        @compile_error("do not format FDEs directly");
    }

    pub fn fmt(fde: Fde, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{
            .fde = fde,
            .macho_file = macho_file,
        } };
    }

    const FormatContext = struct {
        fde: Fde,
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
        const fde = ctx.fde;
        const macho_file = ctx.macho_file;
        try writer.print("@{x} : size({x}) : cie({d}) : {s}", .{
            fde.offset,
            fde.get_size(),
            fde.cie,
            fde.get_atom(macho_file).get_name(macho_file),
        });
        if (!fde.alive) try writer.write_all(" : [*]");
    }

    pub const Index = u32;
};

pub const Iterator = struct {
    data: []const u8,
    pos: u32 = 0,

    pub const Record = struct {
        tag: enum { fde, cie },
        offset: u32,
        size: u32,
    };

    pub fn next(it: *Iterator) !?Record {
        if (it.pos >= it.data.len) return null;

        var stream = std.io.fixed_buffer_stream(it.data[it.pos..]);
        const reader = stream.reader();

        const size = try reader.read_int(u32, .little);
        if (size == 0xFFFFFFFF) @panic("DWARF CFI is 32bit on macOS");

        const id = try reader.read_int(u32, .little);
        const record = Record{
            .tag = if (id == 0) .cie else .fde,
            .offset = it.pos,
            .size = size,
        };
        it.pos += size + 4;

        return record;
    }
};

pub fn calc_size(macho_file: *MachO) !u32 {
    const tracy = trace(@src());
    defer tracy.end();

    var offset: u32 = 0;

    var cies = std.ArrayList(Cie).init(macho_file.base.comp.gpa);
    defer cies.deinit();

    for (macho_file.objects.items) |index| {
        const object = macho_file.get_file(index).?.object;

        outer: for (object.cies.items) |*cie| {
            for (cies.items) |other| {
                if (other.eql(cie.*, macho_file)) {
                    // We already have a CIE record that has the exact same contents, so instead of
                    // duplicating them, we mark this one dead and set its output offset to be
                    // equal to that of the alive record. This way, we won't have to rewrite
                    // Fde.cie_index field when committing the records to file.
                    cie.out_offset = other.out_offset;
                    continue :outer;
                }
            }
            cie.alive = true;
            cie.out_offset = offset;
            offset += cie.get_size();
            try cies.append(cie.*);
        }
    }

    for (macho_file.objects.items) |index| {
        const object = macho_file.get_file(index).?.object;
        for (object.fdes.items) |*fde| {
            if (!fde.alive) continue;
            fde.out_offset = offset;
            offset += fde.get_size();
        }
    }

    return offset;
}

pub fn calc_num_relocs(macho_file: *MachO) u32 {
    const tracy = trace(@src());
    defer tracy.end();

    var nreloc: u32 = 0;

    for (macho_file.objects.items) |index| {
        const object = macho_file.get_file(index).?.object;
        for (object.cies.items) |cie| {
            if (!cie.alive) continue;
            if (cie.get_personality(macho_file)) |_| {
                nreloc += 1; // personality
            }
        }
    }

    return nreloc;
}

pub fn write(macho_file: *MachO, buffer: []u8) void {
    const tracy = trace(@src());
    defer tracy.end();

    const sect = macho_file.sections.items(.header)[macho_file.eh_frame_sect_index.?];
    const addend: i64 = switch (macho_file.get_target().cpu.arch) {
        .x86_64 => 4,
        else => 0,
    };

    for (macho_file.objects.items) |index| {
        const object = macho_file.get_file(index).?.object;
        for (object.cies.items) |cie| {
            if (!cie.alive) continue;

            @memcpy(buffer[cie.out_offset..][0..cie.get_size()], cie.get_data(macho_file));

            if (cie.get_personality(macho_file)) |sym| {
                const offset = cie.out_offset + cie.personality.?.offset;
                const saddr = sect.addr + offset;
                const taddr = sym.get_got_address(macho_file);
                std.mem.write_int(
                    i32,
                    buffer[offset..][0..4],
                    @int_cast(@as(i64, @int_cast(taddr)) - @as(i64, @int_cast(saddr)) + addend),
                    .little,
                );
            }
        }
    }

    for (macho_file.objects.items) |index| {
        const object = macho_file.get_file(index).?.object;
        for (object.fdes.items) |fde| {
            if (!fde.alive) continue;

            @memcpy(buffer[fde.out_offset..][0..fde.get_size()], fde.get_data(macho_file));

            {
                const offset = fde.out_offset + 4;
                const value = offset - fde.get_cie(macho_file).out_offset;
                std.mem.write_int(u32, buffer[offset..][0..4], value, .little);
            }

            {
                const offset = fde.out_offset + 8;
                const saddr = sect.addr + offset;
                const taddr = fde.get_atom(macho_file).get_address(macho_file);
                std.mem.write_int(
                    i64,
                    buffer[offset..][0..8],
                    @as(i64, @int_cast(taddr)) - @as(i64, @int_cast(saddr)),
                    .little,
                );
            }

            if (fde.get_lsda_atom(macho_file)) |atom| {
                const offset = fde.out_offset + fde.lsda_ptr_offset;
                const saddr = sect.addr + offset;
                const taddr = atom.get_address(macho_file) + fde.lsda_offset;
                switch (fde.get_cie(macho_file).lsda_size.?) {
                    .p32 => std.mem.write_int(
                        i32,
                        buffer[offset..][0..4],
                        @int_cast(@as(i64, @int_cast(taddr)) - @as(i64, @int_cast(saddr)) + addend),
                        .little,
                    ),
                    .p64 => std.mem.write_int(
                        i64,
                        buffer[offset..][0..8],
                        @as(i64, @int_cast(taddr)) - @as(i64, @int_cast(saddr)),
                        .little,
                    ),
                }
            }
        }
    }
}

pub fn write_relocs(macho_file: *MachO, code: []u8, relocs: *std.ArrayList(macho.relocation_info)) error{Overflow}!void {
    const tracy = trace(@src());
    defer tracy.end();

    const cpu_arch = macho_file.get_target().cpu.arch;
    const sect = macho_file.sections.items(.header)[macho_file.eh_frame_sect_index.?];
    const addend: i64 = switch (cpu_arch) {
        .x86_64 => 4,
        else => 0,
    };

    for (macho_file.objects.items) |index| {
        const object = macho_file.get_file(index).?.object;
        for (object.cies.items) |cie| {
            if (!cie.alive) continue;

            @memcpy(code[cie.out_offset..][0..cie.get_size()], cie.get_data(macho_file));

            if (cie.get_personality(macho_file)) |sym| {
                const r_address = math.cast(i32, cie.out_offset + cie.personality.?.offset) orelse return error.Overflow;
                const r_symbolnum = math.cast(u24, sym.get_output_symtab_index(macho_file).?) orelse return error.Overflow;
                relocs.append_assume_capacity(.{
                    .r_address = r_address,
                    .r_symbolnum = r_symbolnum,
                    .r_length = 2,
                    .r_extern = 1,
                    .r_pcrel = 1,
                    .r_type = switch (cpu_arch) {
                        .aarch64 => @int_from_enum(macho.reloc_type_arm64.ARM64_RELOC_POINTER_TO_GOT),
                        .x86_64 => @int_from_enum(macho.reloc_type_x86_64.X86_64_RELOC_GOT),
                        else => unreachable,
                    },
                });
            }
        }
    }

    for (macho_file.objects.items) |index| {
        const object = macho_file.get_file(index).?.object;
        for (object.fdes.items) |fde| {
            if (!fde.alive) continue;

            @memcpy(code[fde.out_offset..][0..fde.get_size()], fde.get_data(macho_file));

            {
                const offset = fde.out_offset + 4;
                const value = offset - fde.get_cie(macho_file).out_offset;
                std.mem.write_int(u32, code[offset..][0..4], value, .little);
            }

            {
                const offset = fde.out_offset + 8;
                const saddr = sect.addr + offset;
                const taddr = fde.get_atom(macho_file).get_address(macho_file);
                std.mem.write_int(
                    i64,
                    code[offset..][0..8],
                    @as(i64, @int_cast(taddr)) - @as(i64, @int_cast(saddr)),
                    .little,
                );
            }

            if (fde.get_lsda_atom(macho_file)) |atom| {
                const offset = fde.out_offset + fde.lsda_ptr_offset;
                const saddr = sect.addr + offset;
                const taddr = atom.get_address(macho_file) + fde.lsda_offset;
                switch (fde.get_cie(macho_file).lsda_size.?) {
                    .p32 => std.mem.write_int(
                        i32,
                        code[offset..][0..4],
                        @int_cast(@as(i64, @int_cast(taddr)) - @as(i64, @int_cast(saddr)) + addend),
                        .little,
                    ),
                    .p64 => std.mem.write_int(
                        i64,
                        code[offset..][0..8],
                        @as(i64, @int_cast(taddr)) - @as(i64, @int_cast(saddr)),
                        .little,
                    ),
                }
            }
        }
    }
}

pub const EH_PE = struct {
    pub const absptr = 0x00;
    pub const uleb128 = 0x01;
    pub const udata2 = 0x02;
    pub const udata4 = 0x03;
    pub const udata8 = 0x04;
    pub const sleb128 = 0x09;
    pub const sdata2 = 0x0A;
    pub const sdata4 = 0x0B;
    pub const sdata8 = 0x0C;
    pub const pcrel = 0x10;
    pub const textrel = 0x20;
    pub const datarel = 0x30;
    pub const funcrel = 0x40;
    pub const aligned = 0x50;
    pub const indirect = 0x80;
    pub const omit = 0xFF;
};

const assert = std.debug.assert;
const leb = std.leb;
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const std = @import("std");
const trace = @import("../../tracy.zig").trace;

const Allocator = std.mem.Allocator;
const Atom = @import("Atom.zig");
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
