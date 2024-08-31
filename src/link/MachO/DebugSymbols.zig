allocator: Allocator,
file: fs.File,

symtab_cmd: macho.symtab_command = .{},
uuid_cmd: macho.uuid_command = .{ .uuid = [_]u8{0} ** 16 },

segments: std.ArrayListUnmanaged(macho.segment_command_64) = .{},
sections: std.ArrayListUnmanaged(macho.section_64) = .{},

dwarf_segment_cmd_index: ?u8 = null,
linkedit_segment_cmd_index: ?u8 = null,

debug_info_section_index: ?u8 = null,
debug_abbrev_section_index: ?u8 = null,
debug_str_section_index: ?u8 = null,
debug_aranges_section_index: ?u8 = null,
debug_line_section_index: ?u8 = null,

relocs: std.ArrayListUnmanaged(Reloc) = .{},

/// Output synthetic sections
symtab: std.ArrayListUnmanaged(macho.nlist_64) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

pub const Reloc = struct {
    type: enum {
        direct_load,
        got_load,
    },
    target: u32,
    offset: u64,
    addend: u32,
};

/// You must call this function *after* `ZigObject.init_metadata()`
/// has been called to get a viable debug symbols output.
pub fn init_metadata(self: *DebugSymbols, macho_file: *MachO) !void {
    try self.strtab.append(self.allocator, 0);

    {
        self.dwarf_segment_cmd_index = @as(u8, @int_cast(self.segments.items.len));

        const page_size = macho_file.get_page_size();
        const off = @as(u64, @int_cast(page_size));
        const ideal_size: u16 = 200 + 128 + 160 + 250;
        const needed_size = mem.align_forward(u64, pad_to_ideal(ideal_size), page_size);

        log.debug("found __DWARF segment free space 0x{x} to 0x{x}", .{ off, off + needed_size });

        try self.segments.append(self.allocator, .{
            .segname = make_static_string("__DWARF"),
            .vmsize = needed_size,
            .fileoff = off,
            .filesize = needed_size,
            .cmdsize = @size_of(macho.segment_command_64),
        });
    }

    self.debug_str_section_index = try self.allocate_section("__debug_str", 200, 0);
    self.debug_info_section_index = try self.allocate_section("__debug_info", 200, 0);
    self.debug_abbrev_section_index = try self.allocate_section("__debug_abbrev", 128, 0);
    self.debug_aranges_section_index = try self.allocate_section("__debug_aranges", 160, 4);
    self.debug_line_section_index = try self.allocate_section("__debug_line", 250, 0);

    self.linkedit_segment_cmd_index = @as(u8, @int_cast(self.segments.items.len));
    try self.segments.append(self.allocator, .{
        .segname = make_static_string("__LINKEDIT"),
        .maxprot = macho.PROT.READ,
        .initprot = macho.PROT.READ,
        .cmdsize = @size_of(macho.segment_command_64),
    });
}

fn allocate_section(self: *DebugSymbols, sectname: []const u8, size: u64, alignment: u16) !u8 {
    const segment = self.get_dwarf_segment_ptr();
    var sect = macho.section_64{
        .sectname = make_static_string(sectname),
        .segname = segment.segname,
        .size = @as(u32, @int_cast(size)),
        .@"align" = alignment,
    };
    const alignment_pow_2 = try math.powi(u32, 2, alignment);
    const off = self.find_free_space(size, alignment_pow_2);

    log.debug("found {s},{s} section free space 0x{x} to 0x{x}", .{
        sect.seg_name(),
        sect.sect_name(),
        off,
        off + size,
    });

    sect.offset = @as(u32, @int_cast(off));

    const index = @as(u8, @int_cast(self.sections.items.len));
    try self.sections.append(self.allocator, sect);
    segment.cmdsize += @size_of(macho.section_64);
    segment.nsects += 1;

    return index;
}

pub fn grow_section(
    self: *DebugSymbols,
    sect_index: u8,
    needed_size: u32,
    requires_file_copy: bool,
    macho_file: *MachO,
) !void {
    const sect = self.get_section_ptr(sect_index);

    if (needed_size > self.allocated_size(sect.offset)) {
        const existing_size = sect.size;
        sect.size = 0; // free the space
        const new_offset = self.find_free_space(needed_size, 1);

        log.debug("moving {s} section: {} bytes from 0x{x} to 0x{x}", .{
            sect.sect_name(),
            existing_size,
            sect.offset,
            new_offset,
        });

        if (requires_file_copy) {
            const amt = try self.file.copy_range_all(
                sect.offset,
                self.file,
                new_offset,
                existing_size,
            );
            if (amt != existing_size) return error.InputOutput;
        }

        sect.offset = @as(u32, @int_cast(new_offset));
    }

    sect.size = needed_size;
    self.mark_dirty(sect_index, macho_file);
}

pub fn mark_dirty(self: *DebugSymbols, sect_index: u8, macho_file: *MachO) void {
    if (macho_file.get_zig_object()) |zo| {
        if (self.debug_info_section_index.? == sect_index) {
            zo.debug_info_header_dirty = true;
        } else if (self.debug_line_section_index.? == sect_index) {
            zo.debug_line_header_dirty = true;
        } else if (self.debug_abbrev_section_index.? == sect_index) {
            zo.debug_abbrev_dirty = true;
        } else if (self.debug_str_section_index.? == sect_index) {
            zo.debug_strtab_dirty = true;
        } else if (self.debug_aranges_section_index.? == sect_index) {
            zo.debug_aranges_dirty = true;
        }
    }
}

fn detect_alloc_collision(self: *DebugSymbols, start: u64, size: u64) ?u64 {
    const end = start + pad_to_ideal(size);
    for (self.sections.items) |section| {
        const increased_size = pad_to_ideal(section.size);
        const test_end = section.offset + increased_size;
        if (end > section.offset and start < test_end) {
            return test_end;
        }
    }
    return null;
}

fn find_free_space(self: *DebugSymbols, object_size: u64, min_alignment: u64) u64 {
    const segment = self.get_dwarf_segment_ptr();
    var offset: u64 = segment.fileoff;
    while (self.detect_alloc_collision(offset, object_size)) |item_end| {
        offset = mem.align_forward(u64, item_end, min_alignment);
    }
    return offset;
}

pub fn flush_module(self: *DebugSymbols, macho_file: *MachO) !void {
    for (self.relocs.items) |*reloc| {
        const sym = macho_file.get_symbol(reloc.target);
        const sym_name = sym.get_name(macho_file);
        const addr = switch (reloc.type) {
            .direct_load => sym.get_address(.{}, macho_file),
            .got_load => sym.get_got_address(macho_file),
        };
        const sect = &self.sections.items[self.debug_info_section_index.?];
        const file_offset = sect.offset + reloc.offset;
        log.debug("resolving relocation: {d}@{x} ('{s}') at offset {x}", .{
            reloc.target,
            addr,
            sym_name,
            file_offset,
        });
        try self.file.pwrite_all(mem.as_bytes(&addr), file_offset);
    }

    self.finalize_dwarf_segment(macho_file);
    try self.write_linkedit_segment_data(macho_file);

    // Write load commands
    const ncmds, const sizeofcmds = try self.write_load_commands(macho_file);
    try self.write_header(macho_file, ncmds, sizeofcmds);
}

pub fn deinit(self: *DebugSymbols) void {
    const gpa = self.allocator;
    self.file.close();
    self.segments.deinit(gpa);
    self.sections.deinit(gpa);
    self.relocs.deinit(gpa);
    self.symtab.deinit(gpa);
    self.strtab.deinit(gpa);
}

pub fn swap_remove_relocs(self: *DebugSymbols, target: u32) void {
    // TODO re-implement using a hashmap with free lists
    var last_index: usize = 0;
    while (last_index < self.relocs.items.len) {
        const reloc = self.relocs.items[last_index];
        if (reloc.target == target) {
            _ = self.relocs.swap_remove(last_index);
        } else {
            last_index += 1;
        }
    }
}

fn finalize_dwarf_segment(self: *DebugSymbols, macho_file: *MachO) void {
    const base_vmaddr = blk: {
        // Note that we purposely take the last VM address of the MachO binary including
        // the binary's LINKEDIT segment. This is in contrast to how dsymutil does it
        // which overwrites the the address space taken by the original MachO binary,
        // however at the cost of having LINKEDIT preceed DWARF in dSYM binary which we
        // do not want as we want to be able to incrementally move DWARF sections in the
        // file as we please.
        const last_seg = macho_file.get_linkedit_segment();
        break :blk last_seg.vmaddr + last_seg.vmsize;
    };
    const dwarf_segment = self.get_dwarf_segment_ptr();

    var file_size: u64 = 0;
    for (self.sections.items) |header| {
        file_size = @max(file_size, header.offset + header.size);
    }

    const page_size = macho_file.get_page_size();
    const aligned_size = mem.align_forward(u64, file_size, page_size);
    dwarf_segment.vmaddr = base_vmaddr;
    dwarf_segment.filesize = aligned_size;
    dwarf_segment.vmsize = aligned_size;

    const linkedit = self.get_linkedit_segment_ptr();
    linkedit.vmaddr = mem.align_forward(
        u64,
        dwarf_segment.vmaddr + aligned_size,
        page_size,
    );
    linkedit.fileoff = mem.align_forward(
        u64,
        dwarf_segment.fileoff + aligned_size,
        page_size,
    );
    log.debug("found __LINKEDIT segment free space at 0x{x}", .{linkedit.fileoff});
}

fn write_load_commands(self: *DebugSymbols, macho_file: *MachO) !struct { usize, usize } {
    const gpa = self.allocator;
    const needed_size = load_commands.calc_load_commands_size_dsym(macho_file, self);
    const buffer = try gpa.alloc(u8, needed_size);
    defer gpa.free(buffer);

    var stream = std.io.fixed_buffer_stream(buffer);
    const writer = stream.writer();

    var ncmds: usize = 0;

    // UUID comes first presumably to speed up lookup by the consumer like lldb.
    @memcpy(&self.uuid_cmd.uuid, &macho_file.uuid_cmd.uuid);
    try writer.write_struct(self.uuid_cmd);
    ncmds += 1;

    // Segment and section load commands
    {
        // Write segment/section headers from the binary file first.
        const slice = macho_file.sections.slice();
        var sect_id: usize = 0;
        for (macho_file.segments.items, 0..) |seg, seg_id| {
            if (seg_id == macho_file.linkedit_seg_index.?) break;
            var out_seg = seg;
            out_seg.fileoff = 0;
            out_seg.filesize = 0;
            try writer.write_struct(out_seg);
            for (slice.items(.header)[sect_id..][0..seg.nsects]) |header| {
                var out_header = header;
                out_header.offset = 0;
                try writer.write_struct(out_header);
            }
            sect_id += seg.nsects;
        }
        ncmds += macho_file.segments.items.len - 1;

        // Next, commit DSYM's __LINKEDIT and __DWARF segments headers.
        sect_id = 0;
        for (self.segments.items) |seg| {
            try writer.write_struct(seg);
            for (self.sections.items[sect_id..][0..seg.nsects]) |header| {
                try writer.write_struct(header);
            }
            sect_id += seg.nsects;
        }
        ncmds += self.segments.items.len;
    }

    try writer.write_struct(self.symtab_cmd);
    ncmds += 1;

    assert(stream.pos == needed_size);

    try self.file.pwrite_all(buffer, @size_of(macho.mach_header_64));

    return .{ ncmds, buffer.len };
}

fn write_header(self: *DebugSymbols, macho_file: *MachO, ncmds: usize, sizeofcmds: usize) !void {
    var header: macho.mach_header_64 = .{};
    header.filetype = macho.MH_DSYM;

    switch (macho_file.get_target().cpu.arch) {
        .aarch64 => {
            header.cputype = macho.CPU_TYPE_ARM64;
            header.cpusubtype = macho.CPU_SUBTYPE_ARM_ALL;
        },
        .x86_64 => {
            header.cputype = macho.CPU_TYPE_X86_64;
            header.cpusubtype = macho.CPU_SUBTYPE_X86_64_ALL;
        },
        else => return error.UnsupportedCpuArchitecture,
    }

    header.ncmds = @int_cast(ncmds);
    header.sizeofcmds = @int_cast(sizeofcmds);

    log.debug("writing Mach-O header {}", .{header});

    try self.file.pwrite_all(mem.as_bytes(&header), 0);
}

fn allocated_size(self: *DebugSymbols, start: u64) u64 {
    const seg = self.get_dwarf_segment_ptr();
    assert(start >= seg.fileoff);
    var min_pos: u64 = std.math.max_int(u64);
    for (self.sections.items) |section| {
        if (section.offset <= start) continue;
        if (section.offset < min_pos) min_pos = section.offset;
    }
    return min_pos - start;
}

fn write_linkedit_segment_data(self: *DebugSymbols, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const page_size = macho_file.get_page_size();
    const seg = &self.segments.items[self.linkedit_segment_cmd_index.?];

    var off = math.cast(u32, seg.fileoff) orelse return error.Overflow;
    off = try self.write_symtab(off, macho_file);
    off = mem.align_forward(u32, off, @alignOf(u64));
    off = try self.write_strtab(off);
    seg.filesize = off - seg.fileoff;

    const aligned_size = mem.align_forward(u64, seg.filesize, page_size);
    seg.vmsize = aligned_size;
}

pub fn write_symtab(self: *DebugSymbols, off: u32, macho_file: *MachO) !u32 {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = self.allocator;
    const cmd = &self.symtab_cmd;
    cmd.nsyms = macho_file.symtab_cmd.nsyms;
    cmd.strsize = macho_file.symtab_cmd.strsize;
    cmd.symoff = off;

    try self.symtab.resize(gpa, cmd.nsyms);
    try self.strtab.ensure_unused_capacity(gpa, cmd.strsize - 1);

    if (macho_file.get_zig_object()) |zo| {
        zo.write_symtab(macho_file, self);
    }
    for (macho_file.objects.items) |index| {
        try macho_file.get_file(index).?.write_symtab(macho_file, self);
    }
    for (macho_file.dylibs.items) |index| {
        try macho_file.get_file(index).?.write_symtab(macho_file, self);
    }
    if (macho_file.get_internal_object()) |internal| {
        internal.write_symtab(macho_file, self);
    }

    assert(self.strtab.items.len == cmd.strsize);

    try self.file.pwrite_all(mem.slice_as_bytes(self.symtab.items), cmd.symoff);

    return off + cmd.nsyms * @size_of(macho.nlist_64);
}

pub fn write_strtab(self: *DebugSymbols, off: u32) !u32 {
    const cmd = &self.symtab_cmd;
    cmd.stroff = off;
    try self.file.pwrite_all(self.strtab.items, cmd.stroff);
    return off + cmd.strsize;
}

pub fn get_section_indexes(self: *DebugSymbols, segment_index: u8) struct { start: u8, end: u8 } {
    var start: u8 = 0;
    const nsects = for (self.segments.items, 0..) |seg, i| {
        if (i == segment_index) break @as(u8, @int_cast(seg.nsects));
        start += @as(u8, @int_cast(seg.nsects));
    } else 0;
    return .{ .start = start, .end = start + nsects };
}

fn get_dwarf_segment_ptr(self: *DebugSymbols) *macho.segment_command_64 {
    const index = self.dwarf_segment_cmd_index.?;
    return &self.segments.items[index];
}

fn get_linkedit_segment_ptr(self: *DebugSymbols) *macho.segment_command_64 {
    const index = self.linkedit_segment_cmd_index.?;
    return &self.segments.items[index];
}

pub fn get_section_ptr(self: *DebugSymbols, sect: u8) *macho.section_64 {
    assert(sect < self.sections.items.len);
    return &self.sections.items[sect];
}

pub fn get_section(self: DebugSymbols, sect: u8) macho.section_64 {
    assert(sect < self.sections.items.len);
    return self.sections.items[sect];
}

const DebugSymbols = @This();

const std = @import("std");
const build_options = @import("build_options");
const assert = std.debug.assert;
const fs = std.fs;
const link = @import("../../link.zig");
const load_commands = @import("load_commands.zig");
const log = std.log.scoped(.link_dsym);
const macho = std.macho;
const make_static_string = MachO.make_static_string;
const math = std.math;
const mem = std.mem;
const pad_to_ideal = MachO.pad_to_ideal;
const trace = @import("../../tracy.zig").trace;

const Allocator = mem.Allocator;
const MachO = @import("../MachO.zig");
const StringTable = @import("../StringTable.zig");
const Type = @import("../../type.zig").Type;
