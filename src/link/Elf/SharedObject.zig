path: []const u8,
index: File.Index,

header: ?elf.Elf64_Ehdr = null,
shdrs: std.ArrayListUnmanaged(elf.Elf64_Shdr) = .{},

symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
/// Version symtab contains version strings of the symbols if present.
versyms: std.ArrayListUnmanaged(elf.Elf64_Versym) = .{},
verstrings: std.ArrayListUnmanaged(u32) = .{},

symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
aliases: ?std.ArrayListUnmanaged(u32) = null,
dynamic_table: std.ArrayListUnmanaged(elf.Elf64_Dyn) = .{},

needed: bool,
alive: bool,

output_symtab_ctx: Elf.SymtabCtx = .{},

pub fn is_shared_object(path: []const u8) !bool {
    const file = try std.fs.cwd().open_file(path, .{});
    defer file.close();
    const reader = file.reader();
    const header = reader.read_struct(elf.Elf64_Ehdr) catch return false;
    if (!mem.eql(u8, header.e_ident[0..4], "\x7fELF")) return false;
    if (header.e_ident[elf.EI_VERSION] != 1) return false;
    if (header.e_type != elf.ET.DYN) return false;
    return true;
}

pub fn deinit(self: *SharedObject, allocator: Allocator) void {
    allocator.free(self.path);
    self.shdrs.deinit(allocator);
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    self.versyms.deinit(allocator);
    self.verstrings.deinit(allocator);
    self.symbols.deinit(allocator);
    if (self.aliases) |*aliases| aliases.deinit(allocator);
    self.dynamic_table.deinit(allocator);
}

pub fn parse(self: *SharedObject, elf_file: *Elf, handle: std.fs.File) !void {
    const comp = elf_file.base.comp;
    const gpa = comp.gpa;
    const file_size = (try handle.stat()).size;

    const header_buffer = try Elf.pread_all_alloc(gpa, handle, 0, @size_of(elf.Elf64_Ehdr));
    defer gpa.free(header_buffer);
    self.header = @as(*align(1) const elf.Elf64_Ehdr, @ptr_cast(header_buffer)).*;

    const target = elf_file.base.comp.root_mod.resolved_target.result;
    if (target.cpu.arch != self.header.?.e_machine.to_target_cpu_arch().?) {
        try elf_file.report_parse_error2(
            self.index,
            "invalid cpu architecture: {s}",
            .{@tag_name(self.header.?.e_machine.to_target_cpu_arch().?)},
        );
        return error.InvalidCpuArch;
    }

    const shoff = std.math.cast(usize, self.header.?.e_shoff) orelse return error.Overflow;
    const shnum = std.math.cast(usize, self.header.?.e_shnum) orelse return error.Overflow;
    const shsize = shnum * @size_of(elf.Elf64_Shdr);
    if (file_size < shoff or file_size < shoff + shsize) {
        try elf_file.report_parse_error2(
            self.index,
            "corrupted header: section header table extends past the end of file",
            .{},
        );
        return error.MalformedObject;
    }

    const shdrs_buffer = try Elf.pread_all_alloc(gpa, handle, shoff, shsize);
    defer gpa.free(shdrs_buffer);
    const shdrs = @as([*]align(1) const elf.Elf64_Shdr, @ptr_cast(shdrs_buffer.ptr))[0..shnum];
    try self.shdrs.append_unaligned_slice(gpa, shdrs);

    var dynsym_sect_index: ?u32 = null;
    var dynamic_sect_index: ?u32 = null;
    var versym_sect_index: ?u32 = null;
    var verdef_sect_index: ?u32 = null;
    for (self.shdrs.items, 0..) |shdr, i| {
        if (shdr.sh_type != elf.SHT_NOBITS) {
            if (file_size < shdr.sh_offset or file_size < shdr.sh_offset + shdr.sh_size) {
                try elf_file.report_parse_error2(self.index, "corrupted section header", .{});
                return error.MalformedObject;
            }
        }
        switch (shdr.sh_type) {
            elf.SHT_DYNSYM => dynsym_sect_index = @int_cast(i),
            elf.SHT_DYNAMIC => dynamic_sect_index = @int_cast(i),
            elf.SHT_GNU_VERSYM => versym_sect_index = @int_cast(i),
            elf.SHT_GNU_VERDEF => verdef_sect_index = @int_cast(i),
            else => {},
        }
    }

    if (dynamic_sect_index) |index| {
        const shdr = self.shdrs.items[index];
        const raw = try Elf.pread_all_alloc(gpa, handle, shdr.sh_offset, shdr.sh_size);
        defer gpa.free(raw);
        const num = @div_exact(raw.len, @size_of(elf.Elf64_Dyn));
        const dyntab = @as([*]align(1) const elf.Elf64_Dyn, @ptr_cast(raw.ptr))[0..num];
        try self.dynamic_table.append_unaligned_slice(gpa, dyntab);
    }

    const symtab = if (dynsym_sect_index) |index| blk: {
        const shdr = self.shdrs.items[index];
        const buffer = try Elf.pread_all_alloc(gpa, handle, shdr.sh_offset, shdr.sh_size);
        const nsyms = @div_exact(buffer.len, @size_of(elf.Elf64_Sym));
        break :blk @as([*]align(1) const elf.Elf64_Sym, @ptr_cast(buffer.ptr))[0..nsyms];
    } else &[0]elf.Elf64_Sym{};
    defer gpa.free(symtab);

    const strtab = if (dynsym_sect_index) |index| blk: {
        const symtab_shdr = self.shdrs.items[index];
        const shdr = self.shdrs.items[symtab_shdr.sh_link];
        const buffer = try Elf.pread_all_alloc(gpa, handle, shdr.sh_offset, shdr.sh_size);
        break :blk buffer;
    } else &[0]u8{};
    defer gpa.free(strtab);

    try self.parse_versions(elf_file, handle, .{
        .symtab = symtab,
        .verdef_sect_index = verdef_sect_index,
        .versym_sect_index = versym_sect_index,
    });

    try self.init_symtab(elf_file, .{
        .symtab = symtab,
        .strtab = strtab,
    });
}

fn parse_versions(self: *SharedObject, elf_file: *Elf, handle: std.fs.File, opts: struct {
    symtab: []align(1) const elf.Elf64_Sym,
    verdef_sect_index: ?u32,
    versym_sect_index: ?u32,
}) !void {
    const comp = elf_file.base.comp;
    const gpa = comp.gpa;

    try self.verstrings.resize(gpa, 2);
    self.verstrings.items[elf.VER_NDX_LOCAL] = 0;
    self.verstrings.items[elf.VER_NDX_GLOBAL] = 0;

    if (opts.verdef_sect_index) |shndx| {
        const shdr = self.shdrs.items[shndx];
        const verdefs = try Elf.pread_all_alloc(gpa, handle, shdr.sh_offset, shdr.sh_size);
        defer gpa.free(verdefs);
        const nverdefs = self.verdef_num();
        try self.verstrings.resize(gpa, self.verstrings.items.len + nverdefs);

        var i: u32 = 0;
        var offset: u32 = 0;
        while (i < nverdefs) : (i += 1) {
            const verdef = @as(*align(1) const elf.Elf64_Verdef, @ptr_cast(verdefs.ptr + offset)).*;
            defer offset += verdef.vd_next;
            if (verdef.vd_flags == elf.VER_FLG_BASE) continue; // Skip BASE entry
            const vda_name = if (verdef.vd_cnt > 0)
                @as(*align(1) const elf.Elf64_Verdaux, @ptr_cast(verdefs.ptr + offset + verdef.vd_aux)).vda_name
            else
                0;
            self.verstrings.items[verdef.vd_ndx] = vda_name;
        }
    }

    try self.versyms.ensure_total_capacity_precise(gpa, opts.symtab.len);

    if (opts.versym_sect_index) |shndx| {
        const shdr = self.shdrs.items[shndx];
        const versyms_raw = try Elf.pread_all_alloc(gpa, handle, shdr.sh_offset, shdr.sh_size);
        defer gpa.free(versyms_raw);
        const nversyms = @div_exact(versyms_raw.len, @size_of(elf.Elf64_Versym));
        const versyms = @as([*]align(1) const elf.Elf64_Versym, @ptr_cast(versyms_raw.ptr))[0..nversyms];
        for (versyms) |ver| {
            const normalized_ver = if (ver & elf.VERSYM_VERSION >= self.verstrings.items.len - 1)
                elf.VER_NDX_GLOBAL
            else
                ver;
            self.versyms.append_assume_capacity(normalized_ver);
        }
    } else for (0..opts.symtab.len) |_| {
        self.versyms.append_assume_capacity(elf.VER_NDX_GLOBAL);
    }
}

fn init_symtab(self: *SharedObject, elf_file: *Elf, opts: struct {
    symtab: []align(1) const elf.Elf64_Sym,
    strtab: []const u8,
}) !void {
    const comp = elf_file.base.comp;
    const gpa = comp.gpa;

    try self.strtab.append_slice(gpa, opts.strtab);
    try self.symtab.ensure_total_capacity_precise(gpa, opts.symtab.len);
    try self.symbols.ensure_total_capacity_precise(gpa, opts.symtab.len);

    for (opts.symtab, 0..) |sym, i| {
        const hidden = self.versyms.items[i] & elf.VERSYM_HIDDEN != 0;
        const name = self.get_string(sym.st_name);
        // We need to garble up the name so that we don't pick this symbol
        // during symbol resolution. Thank you GNU!
        const name_off = if (hidden) blk: {
            const mangled = try std.fmt.alloc_print(gpa, "{s}@{s}", .{
                name,
                self.version_string(self.versyms.items[i]),
            });
            defer gpa.free(mangled);
            const name_off = @as(u32, @int_cast(self.strtab.items.len));
            try self.strtab.writer(gpa).print("{s}\x00", .{mangled});
            break :blk name_off;
        } else sym.st_name;
        const out_sym = self.symtab.add_one_assume_capacity();
        out_sym.* = sym;
        out_sym.st_name = name_off;
        const gop = try elf_file.get_or_put_global(self.get_string(name_off));
        self.symbols.add_one_assume_capacity().* = gop.index;
    }
}

pub fn resolve_symbols(self: *SharedObject, elf_file: *Elf) void {
    for (self.globals(), 0..) |index, i| {
        const esym_index = @as(u32, @int_cast(i));
        const this_sym = self.symtab.items[esym_index];

        if (this_sym.st_shndx == elf.SHN_UNDEF) continue;

        const global = elf_file.symbol(index);
        if (self.as_file().symbol_rank(this_sym, false) < global.symbol_rank(elf_file)) {
            global.value = @int_cast(this_sym.st_value);
            global.atom_index = 0;
            global.esym_index = esym_index;
            global.version_index = self.versyms.items[esym_index];
            global.file_index = self.index;
        }
    }
}

pub fn mark_live(self: *SharedObject, elf_file: *Elf) void {
    for (self.globals(), 0..) |index, i| {
        const sym = self.symtab.items[i];
        if (sym.st_shndx != elf.SHN_UNDEF) continue;

        const global = elf_file.symbol(index);
        const file = global.file(elf_file) orelse continue;
        const should_drop = switch (file) {
            .shared_object => |sh| !sh.needed and sym.st_bind() == elf.STB_WEAK,
            else => false,
        };
        if (!should_drop and !file.is_alive()) {
            file.set_alive();
            file.mark_live(elf_file);
        }
    }
}

pub fn globals(self: SharedObject) []const Symbol.Index {
    return self.symbols.items;
}

pub fn update_symtab_size(self: *SharedObject, elf_file: *Elf) !void {
    for (self.globals()) |global_index| {
        const global = elf_file.symbol(global_index);
        const file_ptr = global.file(elf_file) orelse continue;
        if (file_ptr.index() != self.index) continue;
        if (global.is_local(elf_file)) continue;
        global.flags.output_symtab = true;
        try global.add_extra(.{ .symtab = self.output_symtab_ctx.nglobals }, elf_file);
        self.output_symtab_ctx.nglobals += 1;
        self.output_symtab_ctx.strsize += @as(u32, @int_cast(global.name(elf_file).len)) + 1;
    }
}

pub fn write_symtab(self: SharedObject, elf_file: *Elf) void {
    for (self.globals()) |global_index| {
        const global = elf_file.symbol(global_index);
        const file_ptr = global.file(elf_file) orelse continue;
        if (file_ptr.index() != self.index) continue;
        const idx = global.output_symtab_index(elf_file) orelse continue;
        const st_name = @as(u32, @int_cast(elf_file.strtab.items.len));
        elf_file.strtab.append_slice_assume_capacity(global.name(elf_file));
        elf_file.strtab.append_assume_capacity(0);
        const out_sym = &elf_file.symtab.items[idx];
        out_sym.st_name = st_name;
        global.set_output_sym(elf_file, out_sym);
    }
}

pub fn version_string(self: SharedObject, index: elf.Elf64_Versym) [:0]const u8 {
    const off = self.verstrings.items[index & elf.VERSYM_VERSION];
    return self.get_string(off);
}

pub fn as_file(self: *SharedObject) File {
    return .{ .shared_object = self };
}

fn verdef_num(self: *SharedObject) u32 {
    for (self.dynamic_table.items) |entry| switch (entry.d_tag) {
        elf.DT_VERDEFNUM => return @as(u32, @int_cast(entry.d_val)),
        else => {},
    };
    return 0;
}

pub fn soname(self: *SharedObject) []const u8 {
    for (self.dynamic_table.items) |entry| switch (entry.d_tag) {
        elf.DT_SONAME => return self.get_string(@as(u32, @int_cast(entry.d_val))),
        else => {},
    };
    return std.fs.path.basename(self.path);
}

pub fn init_symbol_aliases(self: *SharedObject, elf_file: *Elf) !void {
    assert(self.aliases == null);

    const SortAlias = struct {
        pub fn less_than(ctx: *Elf, lhs: Symbol.Index, rhs: Symbol.Index) bool {
            const lhs_sym = ctx.symbol(lhs).elf_sym(ctx);
            const rhs_sym = ctx.symbol(rhs).elf_sym(ctx);
            return lhs_sym.st_value < rhs_sym.st_value;
        }
    };

    const comp = elf_file.base.comp;
    const gpa = comp.gpa;
    var aliases = std.ArrayList(Symbol.Index).init(gpa);
    defer aliases.deinit();
    try aliases.ensure_total_capacity_precise(self.globals().len);

    for (self.globals()) |index| {
        const global = elf_file.symbol(index);
        const global_file = global.file(elf_file) orelse continue;
        if (global_file.index() != self.index) continue;
        aliases.append_assume_capacity(index);
    }

    std.mem.sort(u32, aliases.items, elf_file, SortAlias.less_than);

    self.aliases = aliases.move_to_unmanaged();
}

pub fn symbol_aliases(self: *SharedObject, index: u32, elf_file: *Elf) []const u32 {
    assert(self.aliases != null);

    const symbol = elf_file.symbol(index).elf_sym(elf_file);
    const aliases = self.aliases.?;

    const start = for (aliases.items, 0..) |alias, i| {
        const alias_sym = elf_file.symbol(alias).elf_sym(elf_file);
        if (symbol.st_value == alias_sym.st_value) break i;
    } else aliases.items.len;

    const end = for (aliases.items[start..], 0..) |alias, i| {
        const alias_sym = elf_file.symbol(alias).elf_sym(elf_file);
        if (symbol.st_value < alias_sym.st_value) break i + start;
    } else aliases.items.len;

    return aliases.items[start..end];
}

pub fn get_string(self: SharedObject, off: u32) [:0]const u8 {
    assert(off < self.strtab.items.len);
    return mem.slice_to(@as([*:0]const u8, @ptr_cast(self.strtab.items.ptr + off)), 0);
}

pub fn format(
    self: SharedObject,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = self;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compile_error("do not format shared objects directly");
}

pub fn fmt_symtab(self: SharedObject, elf_file: *Elf) std.fmt.Formatter(format_symtab) {
    return .{ .data = .{
        .shared = self,
        .elf_file = elf_file,
    } };
}

const FormatContext = struct {
    shared: SharedObject,
    elf_file: *Elf,
};

fn format_symtab(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const shared = ctx.shared;
    try writer.write_all("  globals\n");
    for (shared.symbols.items) |index| {
        const global = ctx.elf_file.symbol(index);
        try writer.print("    {}\n", .{global.fmt(ctx.elf_file)});
    }
}

const SharedObject = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");
const File = @import("file.zig").File;
const Symbol = @import("Symbol.zig");
