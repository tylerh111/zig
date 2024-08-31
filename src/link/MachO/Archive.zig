objects: std.ArrayListUnmanaged(Object) = .{},

pub fn is_archive(path: []const u8, fat_arch: ?fat.Arch) !bool {
    const file = try std.fs.cwd().open_file(path, .{});
    defer file.close();
    if (fat_arch) |arch| {
        try file.seek_to(arch.offset);
    }
    const magic = file.reader().read_bytes_no_eof(SARMAG) catch return false;
    if (!mem.eql(u8, &magic, ARMAG)) return false;
    return true;
}

pub fn deinit(self: *Archive, allocator: Allocator) void {
    self.objects.deinit(allocator);
}

pub fn parse(self: *Archive, macho_file: *MachO, path: []const u8, handle_index: File.HandleIndex, fat_arch: ?fat.Arch) !void {
    const gpa = macho_file.base.comp.gpa;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    const handle = macho_file.get_file_handle(handle_index);
    const offset = if (fat_arch) |ar| ar.offset else 0;
    const end_pos = if (fat_arch) |ar| offset + ar.size else (try handle.stat()).size;

    var pos: usize = offset + SARMAG;
    while (true) {
        if (pos >= end_pos) break;
        if (!mem.is_aligned(pos, 2)) pos += 1;

        var hdr_buffer: [@size_of(ar_hdr)]u8 = undefined;
        {
            const amt = try handle.pread_all(&hdr_buffer, pos);
            if (amt != @size_of(ar_hdr)) return error.InputOutput;
        }
        const hdr = @as(*align(1) const ar_hdr, @ptr_cast(&hdr_buffer)).*;
        pos += @size_of(ar_hdr);

        if (!mem.eql(u8, &hdr.ar_fmag, ARFMAG)) {
            try macho_file.report_parse_error(path, "invalid header delimiter: expected '{s}', found '{s}'", .{
                std.fmt.fmt_slice_escape_lower(ARFMAG), std.fmt.fmt_slice_escape_lower(&hdr.ar_fmag),
            });
            return error.MalformedArchive;
        }

        var hdr_size = try hdr.size();
        const name = name: {
            if (hdr.name()) |n| break :name n;
            if (try hdr.name_length()) |len| {
                hdr_size -= len;
                const buf = try arena.allocator().alloc(u8, len);
                const amt = try handle.pread_all(buf, pos);
                if (amt != len) return error.InputOutput;
                pos += len;
                const actual_len = mem.index_of_scalar(u8, buf, @as(u8, 0)) orelse len;
                break :name buf[0..actual_len];
            }
            unreachable;
        };
        defer pos += hdr_size;

        if (mem.eql(u8, name, SYMDEF) or
            mem.eql(u8, name, SYMDEF64) or
            mem.eql(u8, name, SYMDEF_SORTED) or
            mem.eql(u8, name, SYMDEF64_SORTED)) continue;

        const object = Object{
            .archive = .{
                .path = try gpa.dupe(u8, path),
                .offset = pos,
                .size = hdr_size,
            },
            .path = try gpa.dupe(u8, name),
            .file_handle = handle_index,
            .index = undefined,
            .alive = false,
            .mtime = hdr.date() catch 0,
        };

        log.debug("extracting object '{s}' from archive '{s}'", .{ object.path, path });

        try self.objects.append(gpa, object);
    }
}

pub fn write_header(
    object_name: []const u8,
    object_size: usize,
    format: Format,
    writer: anytype,
) !void {
    var hdr: ar_hdr = .{
        .ar_name = undefined,
        .ar_date = undefined,
        .ar_uid = undefined,
        .ar_gid = undefined,
        .ar_mode = undefined,
        .ar_size = undefined,
        .ar_fmag = undefined,
    };
    @memset(mem.as_bytes(&hdr), 0x20);
    inline for (@typeInfo(ar_hdr).Struct.fields) |field| {
        var stream = std.io.fixed_buffer_stream(&@field(hdr, field.name));
        stream.writer().print("0", .{}) catch unreachable;
    }
    @memcpy(&hdr.ar_fmag, ARFMAG);

    const object_name_len = mem.align_forward(usize, object_name.len + 1, ptr_width(format));
    const total_object_size = object_size + object_name_len;

    {
        var stream = std.io.fixed_buffer_stream(&hdr.ar_name);
        stream.writer().print("#1/{d}", .{object_name_len}) catch unreachable;
    }
    {
        var stream = std.io.fixed_buffer_stream(&hdr.ar_size);
        stream.writer().print("{d}", .{total_object_size}) catch unreachable;
    }

    try writer.write_all(mem.as_bytes(&hdr));
    try writer.print("{s}\x00", .{object_name});

    const padding = object_name_len - object_name.len - 1;
    if (padding > 0) {
        try writer.write_byte_ntimes(0, padding);
    }
}

// Archive files start with the ARMAG identifying string.  Then follows a
// `struct ar_hdr', and as many bytes of member file data as its `ar_size'
// member indicates, for each member file.
/// String that begins an archive file.
pub const ARMAG: *const [SARMAG:0]u8 = "!<arch>\n";
/// Size of that string.
pub const SARMAG: u4 = 8;

/// String in ar_fmag at the end of each header.
const ARFMAG: *const [2:0]u8 = "`\n";

pub const SYMDEF = "__.SYMDEF";
pub const SYMDEF64 = "__.SYMDEF_64";
pub const SYMDEF_SORTED = "__.SYMDEF SORTED";
pub const SYMDEF64_SORTED = "__.SYMDEF_64 SORTED";

pub const ar_hdr = extern struct {
    /// Member file name, sometimes / terminated.
    ar_name: [16]u8,

    /// File date, decimal seconds since Epoch.
    ar_date: [12]u8,

    /// User ID, in ASCII format.
    ar_uid: [6]u8,

    /// Group ID, in ASCII format.
    ar_gid: [6]u8,

    /// File mode, in ASCII octal.
    ar_mode: [8]u8,

    /// File size, in ASCII decimal.
    ar_size: [10]u8,

    /// Always contains ARFMAG.
    ar_fmag: [2]u8,

    fn date(self: ar_hdr) !u64 {
        const value = mem.trim_right(u8, &self.ar_date, &[_]u8{@as(u8, 0x20)});
        return std.fmt.parse_int(u64, value, 10);
    }

    fn size(self: ar_hdr) !u32 {
        const value = mem.trim_right(u8, &self.ar_size, &[_]u8{@as(u8, 0x20)});
        return std.fmt.parse_int(u32, value, 10);
    }

    fn name(self: *const ar_hdr) ?[]const u8 {
        const value = &self.ar_name;
        if (mem.starts_with(u8, value, "#1/")) return null;
        const sentinel = mem.index_of_scalar(u8, value, '/') orelse value.len;
        return value[0..sentinel];
    }

    fn name_length(self: ar_hdr) !?u32 {
        const value = &self.ar_name;
        if (!mem.starts_with(u8, value, "#1/")) return null;
        const trimmed = mem.trim_right(u8, self.ar_name["#1/".len..], &[_]u8{0x20});
        return try std.fmt.parse_int(u32, trimmed, 10);
    }
};

pub const ArSymtab = struct {
    entries: std.ArrayListUnmanaged(Entry) = .{},
    strtab: StringTable = .{},

    pub fn deinit(ar: *ArSymtab, allocator: Allocator) void {
        ar.entries.deinit(allocator);
        ar.strtab.deinit(allocator);
    }

    pub fn sort(ar: *ArSymtab) void {
        mem.sort(Entry, ar.entries.items, {}, Entry.less_than);
    }

    pub fn size(ar: ArSymtab, format: Format) usize {
        const ptr_width = ptr_width(format);
        return ptr_width + ar.entries.items.len * 2 * ptr_width + ptr_width + mem.align_forward(usize, ar.strtab.buffer.items.len, ptr_width);
    }

    pub fn write(ar: ArSymtab, format: Format, macho_file: *MachO, writer: anytype) !void {
        const ptr_width = ptr_width(format);
        // Header
        try write_header(SYMDEF, ar.size(format), format, writer);
        // Symtab size
        try write_int(format, ar.entries.items.len * 2 * ptr_width, writer);
        // Symtab entries
        for (ar.entries.items) |entry| {
            const file_off = switch (macho_file.get_file(entry.file).?) {
                .zig_object => |x| x.output_ar_state.file_off,
                .object => |x| x.output_ar_state.file_off,
                else => unreachable,
            };
            // Name offset
            try write_int(format, entry.off, writer);
            // File offset
            try write_int(format, file_off, writer);
        }
        // Strtab size
        const strtab_size = mem.align_forward(usize, ar.strtab.buffer.items.len, ptr_width);
        const padding = strtab_size - ar.strtab.buffer.items.len;
        try write_int(format, strtab_size, writer);
        // Strtab
        try writer.write_all(ar.strtab.buffer.items);
        if (padding > 0) {
            try writer.write_byte_ntimes(0, padding);
        }
    }

    const FormatContext = struct {
        ar: ArSymtab,
        macho_file: *MachO,
    };

    pub fn fmt(ar: ArSymtab, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{ .ar = ar, .macho_file = macho_file } };
    }

    fn format2(
        ctx: FormatContext,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        const ar = ctx.ar;
        const macho_file = ctx.macho_file;
        for (ar.entries.items, 0..) |entry, i| {
            const name = ar.strtab.get_assume_exists(entry.off);
            const file = macho_file.get_file(entry.file).?;
            try writer.print("  {d}: {s} in file({d})({})\n", .{ i, name, entry.file, file.fmt_path() });
        }
    }

    const Entry = struct {
        /// Symbol name offset
        off: u32,
        /// Exporting file
        file: File.Index,

        pub fn less_than(ctx: void, lhs: Entry, rhs: Entry) bool {
            _ = ctx;
            if (lhs.off == rhs.off) return lhs.file < rhs.file;
            return lhs.off < rhs.off;
        }
    };
};

pub const Format = enum {
    p32,
    p64,
};

pub fn ptr_width(format: Format) usize {
    return switch (format) {
        .p32 => @as(usize, 4),
        .p64 => 8,
    };
}

pub fn write_int(format: Format, value: u64, writer: anytype) !void {
    switch (format) {
        .p32 => try writer.write_int(u32, std.math.cast(u32, value) orelse return error.Overflow, .little),
        .p64 => try writer.write_int(u64, value, .little),
    }
}

pub const ArState = struct {
    /// File offset of the ar_hdr describing the contributing
    /// object in the archive.
    file_off: u64 = 0,

    /// Total size of the contributing object (excludes ar_hdr and long name with padding).
    size: u64 = 0,
};

const fat = @import("fat.zig");
const link = @import("../../link.zig");
const log = std.log.scoped(.link);
const macho = std.macho;
const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Archive = @This();
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const StringTable = @import("../StringTable.zig");
