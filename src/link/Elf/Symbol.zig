//! Represents a defined symbol.

/// Allocated address value of this symbol.
value: i64 = 0,

/// Offset into the linker's string table.
name_offset: u32 = 0,

/// Index of file where this symbol is defined.
file_index: File.Index = 0,

/// Index of atom containing this symbol.
/// Index of 0 means there is no associated atom with this symbol.
/// Use `atom` to get the pointer to the atom.
atom_index: Atom.Index = 0,

/// Assigned output section index for this symbol.
output_section_index: u32 = 0,

/// Index of the source symbol this symbol references.
/// Use `elf_sym` to pull the source symbol from the relevant file.
esym_index: Index = 0,

/// Index of the source version symbol this symbol references if any.
/// If the symbol is unversioned it will have either VER_NDX_LOCAL or VER_NDX_GLOBAL.
version_index: elf.Elf64_Versym = elf.VER_NDX_LOCAL,

/// Misc flags for the symbol packaged as packed struct for compression.
flags: Flags = .{},

extra_index: u32 = 0,

pub fn is_abs(symbol: Symbol, elf_file: *Elf) bool {
    const file_ptr = symbol.file(elf_file).?;
    if (file_ptr == .shared_object) return symbol.elf_sym(elf_file).st_shndx == elf.SHN_ABS;
    return !symbol.flags.import and symbol.atom(elf_file) == null and
        symbol.merge_subsection(elf_file) == null and symbol.output_shndx() == null and
        file_ptr != .linker_defined;
}

pub fn output_shndx(symbol: Symbol) ?u32 {
    if (symbol.output_section_index == 0) return null;
    return symbol.output_section_index;
}

pub fn is_local(symbol: Symbol, elf_file: *Elf) bool {
    if (elf_file.base.is_relocatable()) return symbol.elf_sym(elf_file).st_bind() == elf.STB_LOCAL;
    return !(symbol.flags.import or symbol.flags.@"export");
}

pub fn is_ifunc(symbol: Symbol, elf_file: *Elf) bool {
    return symbol.type(elf_file) == elf.STT_GNU_IFUNC;
}

pub fn @"type"(symbol: Symbol, elf_file: *Elf) u4 {
    const esym = symbol.elf_sym(elf_file);
    const file_ptr = symbol.file(elf_file).?;
    if (esym.st_type() == elf.STT_GNU_IFUNC and file_ptr == .shared_object) return elf.STT_FUNC;
    return esym.st_type();
}

pub fn name(symbol: Symbol, elf_file: *Elf) [:0]const u8 {
    if (symbol.flags.global) return elf_file.strings.get_assume_exists(symbol.name_offset);
    const file_ptr = symbol.file(elf_file).?;
    return switch (file_ptr) {
        inline else => |x| x.get_string(symbol.name_offset),
    };
}

pub fn atom(symbol: Symbol, elf_file: *Elf) ?*Atom {
    return elf_file.atom(symbol.atom_index);
}

pub fn merge_subsection(symbol: Symbol, elf_file: *Elf) ?*MergeSubsection {
    if (!symbol.flags.merge_subsection) return null;
    const extras = symbol.extra(elf_file).?;
    return elf_file.merge_subsection(extras.subsection);
}

pub fn file(symbol: Symbol, elf_file: *Elf) ?File {
    return elf_file.file(symbol.file_index);
}

pub fn elf_sym(symbol: Symbol, elf_file: *Elf) elf.Elf64_Sym {
    const file_ptr = symbol.file(elf_file).?;
    return switch (file_ptr) {
        .zig_object => |x| x.elf_sym(symbol.esym_index).*,
        inline else => |x| x.symtab.items[symbol.esym_index],
    };
}

pub fn symbol_rank(symbol: Symbol, elf_file: *Elf) u32 {
    const file_ptr = symbol.file(elf_file) orelse return std.math.max_int(u32);
    const sym = symbol.elf_sym(elf_file);
    const in_archive = switch (file_ptr) {
        .object => |x| !x.alive,
        else => false,
    };
    return file_ptr.symbol_rank(sym, in_archive);
}

pub fn address(symbol: Symbol, opts: struct { plt: bool = true }, elf_file: *Elf) i64 {
    if (symbol.merge_subsection(elf_file)) |msub| {
        if (!msub.alive) return 0;
        return msub.address(elf_file) + symbol.value;
    }
    if (symbol.flags.has_copy_rel) {
        return symbol.copy_rel_address(elf_file);
    }
    if (symbol.flags.has_plt and opts.plt) {
        if (!symbol.flags.is_canonical and symbol.flags.has_got) {
            // We have a non-lazy bound function pointer, use that!
            return symbol.plt_got_address(elf_file);
        }
        // Lazy-bound function it is!
        return symbol.plt_address(elf_file);
    }
    if (symbol.atom(elf_file)) |atom_ptr| {
        if (!atom_ptr.flags.alive) {
            if (mem.eql(u8, atom_ptr.name(elf_file), ".eh_frame")) {
                const sym_name = symbol.name(elf_file);
                const sh_addr, const sh_size = blk: {
                    const shndx = elf_file.eh_frame_section_index orelse break :blk .{ 0, 0 };
                    const shdr = elf_file.shdrs.items[shndx];
                    break :blk .{ shdr.sh_addr, shdr.sh_size };
                };
                if (mem.starts_with(u8, sym_name, "__EH_FRAME_BEGIN__") or
                    mem.starts_with(u8, sym_name, "__EH_FRAME_LIST__") or
                    mem.starts_with(u8, sym_name, ".eh_frame_seg") or
                    symbol.elf_sym(elf_file).st_type() == elf.STT_SECTION)
                {
                    return @int_cast(sh_addr);
                }

                if (mem.starts_with(u8, sym_name, "__FRAME_END__") or
                    mem.starts_with(u8, sym_name, "__EH_FRAME_LIST_END__"))
                {
                    return @int_cast(sh_addr + sh_size);
                }

                // TODO I think we potentially should error here
            }

            return 0;
        }
        return atom_ptr.address(elf_file) + symbol.value;
    }
    return symbol.value;
}

pub fn output_symtab_index(symbol: Symbol, elf_file: *Elf) ?u32 {
    if (!symbol.flags.output_symtab) return null;
    const file_ptr = symbol.file(elf_file).?;
    const symtab_ctx = switch (file_ptr) {
        inline else => |x| x.output_symtab_ctx,
    };
    const idx = symbol.extra(elf_file).?.symtab;
    return if (symbol.is_local(elf_file)) idx + symtab_ctx.ilocal else idx + symtab_ctx.iglobal;
}

pub fn got_address(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.has_got) return 0;
    const extras = symbol.extra(elf_file).?;
    const entry = elf_file.got.entries.items[extras.got];
    return entry.address(elf_file);
}

pub fn plt_got_address(symbol: Symbol, elf_file: *Elf) i64 {
    if (!(symbol.flags.has_plt and symbol.flags.has_got)) return 0;
    const extras = symbol.extra(elf_file).?;
    const shdr = elf_file.shdrs.items[elf_file.plt_got_section_index.?];
    const cpu_arch = elf_file.get_target().cpu.arch;
    return @int_cast(shdr.sh_addr + extras.plt_got * PltGotSection.entry_size(cpu_arch));
}

pub fn plt_address(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.has_plt) return 0;
    const extras = symbol.extra(elf_file).?;
    const shdr = elf_file.shdrs.items[elf_file.plt_section_index.?];
    const cpu_arch = elf_file.get_target().cpu.arch;
    return @int_cast(shdr.sh_addr + extras.plt * PltSection.entry_size(cpu_arch) + PltSection.preamble_size(cpu_arch));
}

pub fn got_plt_address(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.has_plt) return 0;
    const extras = symbol.extra(elf_file).?;
    const shdr = elf_file.shdrs.items[elf_file.got_plt_section_index.?];
    return @int_cast(shdr.sh_addr + extras.plt * 8 + GotPltSection.preamble_size);
}

pub fn copy_rel_address(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.has_copy_rel) return 0;
    const shdr = elf_file.shdrs.items[elf_file.copy_rel_section_index.?];
    return @as(i64, @int_cast(shdr.sh_addr)) + symbol.value;
}

pub fn tls_gd_address(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.has_tlsgd) return 0;
    const extras = symbol.extra(elf_file).?;
    const entry = elf_file.got.entries.items[extras.tlsgd];
    return entry.address(elf_file);
}

pub fn got_tp_address(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.has_gottp) return 0;
    const extras = symbol.extra(elf_file).?;
    const entry = elf_file.got.entries.items[extras.gottp];
    return entry.address(elf_file);
}

pub fn tls_desc_address(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.has_tlsdesc) return 0;
    const extras = symbol.extra(elf_file).?;
    const entry = elf_file.got.entries.items[extras.tlsdesc];
    return entry.address(elf_file);
}

const GetOrCreateZigGotEntryResult = struct {
    found_existing: bool,
    index: ZigGotSection.Index,
};

pub fn get_or_create_zig_got_entry(symbol: *Symbol, symbol_index: Index, elf_file: *Elf) !GetOrCreateZigGotEntryResult {
    assert(!elf_file.base.is_relocatable());
    assert(symbol.flags.needs_zig_got);
    if (symbol.flags.has_zig_got) return .{ .found_existing = true, .index = symbol.extra(elf_file).?.zig_got };
    const index = try elf_file.zig_got.add_symbol(symbol_index, elf_file);
    return .{ .found_existing = false, .index = index };
}

pub fn zig_got_address(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.has_zig_got) return 0;
    const extras = symbol.extra(elf_file).?;
    return elf_file.zig_got.entry_address(extras.zig_got, elf_file);
}

pub fn dso_alignment(symbol: Symbol, elf_file: *Elf) !u64 {
    const file_ptr = symbol.file(elf_file) orelse return 0;
    assert(file_ptr == .shared_object);
    const shared_object = file_ptr.shared_object;
    const esym = symbol.elf_sym(elf_file);
    const shdr = shared_object.shdrs.items[esym.st_shndx];
    const alignment = @max(1, shdr.sh_addralign);
    return if (esym.st_value == 0)
        alignment
    else
        @min(alignment, try std.math.powi(u64, 2, @ctz(esym.st_value)));
}

const AddExtraOpts = struct {
    got: ?u32 = null,
    plt: ?u32 = null,
    plt_got: ?u32 = null,
    dynamic: ?u32 = null,
    symtab: ?u32 = null,
    copy_rel: ?u32 = null,
    tlsgd: ?u32 = null,
    gottp: ?u32 = null,
    tlsdesc: ?u32 = null,
    zig_got: ?u32 = null,
    subsection: ?u32 = null,
};

pub fn add_extra(symbol: *Symbol, opts: AddExtraOpts, elf_file: *Elf) !void {
    if (symbol.extra(elf_file) == null) {
        symbol.extra_index = try elf_file.add_symbol_extra(.{});
    }
    var extras = symbol.extra(elf_file).?;
    inline for (@typeInfo(@TypeOf(opts)).Struct.fields) |field| {
        if (@field(opts, field.name)) |x| {
            @field(extras, field.name) = x;
        }
    }
    symbol.set_extra(extras, elf_file);
}

pub fn extra(symbol: Symbol, elf_file: *Elf) ?Extra {
    return elf_file.symbol_extra(symbol.extra_index);
}

pub fn set_extra(symbol: Symbol, extras: Extra, elf_file: *Elf) void {
    elf_file.set_symbol_extra(symbol.extra_index, extras);
}

pub fn set_output_sym(symbol: Symbol, elf_file: *Elf, out: *elf.Elf64_Sym) void {
    const file_ptr = symbol.file(elf_file).?;
    const esym = symbol.elf_sym(elf_file);
    const st_type = symbol.type(elf_file);
    const st_bind: u8 = blk: {
        if (symbol.is_local(elf_file)) break :blk 0;
        if (symbol.flags.weak) break :blk elf.STB_WEAK;
        if (file_ptr == .shared_object) break :blk elf.STB_GLOBAL;
        break :blk esym.st_bind();
    };
    const st_shndx: u16 = blk: {
        if (symbol.flags.has_copy_rel) break :blk @int_cast(elf_file.copy_rel_section_index.?);
        if (file_ptr == .shared_object or esym.st_shndx == elf.SHN_UNDEF) break :blk elf.SHN_UNDEF;
        if (elf_file.base.is_relocatable() and esym.st_shndx == elf.SHN_COMMON) break :blk elf.SHN_COMMON;
        if (symbol.merge_subsection(elf_file)) |msub| break :blk @int_cast(msub.merge_section(elf_file).output_section_index);
        if (symbol.atom(elf_file) == null and file_ptr != .linker_defined) break :blk elf.SHN_ABS;
        break :blk @int_cast(symbol.output_shndx() orelse elf.SHN_UNDEF);
    };
    const st_value = blk: {
        if (symbol.flags.has_copy_rel) break :blk symbol.address(.{}, elf_file);
        if (file_ptr == .shared_object or esym.st_shndx == elf.SHN_UNDEF) {
            if (symbol.flags.is_canonical) break :blk symbol.address(.{}, elf_file);
            break :blk 0;
        }
        if (st_shndx == elf.SHN_ABS or st_shndx == elf.SHN_COMMON) break :blk symbol.address(.{ .plt = false }, elf_file);
        const shdr = elf_file.shdrs.items[st_shndx];
        if (shdr.sh_flags & elf.SHF_TLS != 0 and file_ptr != .linker_defined)
            break :blk symbol.address(.{ .plt = false }, elf_file) - elf_file.tls_address();
        break :blk symbol.address(.{ .plt = false }, elf_file);
    };
    out.st_info = (st_bind << 4) | st_type;
    out.st_other = esym.st_other;
    out.st_shndx = st_shndx;
    out.st_value = @int_cast(st_value);
    out.st_size = esym.st_size;
}

pub fn format(
    symbol: Symbol,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = symbol;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compile_error("do not format symbols directly");
}

const FormatContext = struct {
    symbol: Symbol,
    elf_file: *Elf,
};

pub fn fmt_name(symbol: Symbol, elf_file: *Elf) std.fmt.Formatter(format_name) {
    return .{ .data = .{
        .symbol = symbol,
        .elf_file = elf_file,
    } };
}

fn format_name(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const elf_file = ctx.elf_file;
    const symbol = ctx.symbol;
    try writer.write_all(symbol.name(elf_file));
    switch (symbol.version_index & elf.VERSYM_VERSION) {
        elf.VER_NDX_LOCAL, elf.VER_NDX_GLOBAL => {},
        else => {
            const file_ptr = symbol.file(elf_file).?;
            assert(file_ptr == .shared_object);
            const shared_object = file_ptr.shared_object;
            try writer.print("@{s}", .{shared_object.version_string(symbol.version_index)});
        },
    }
}

pub fn fmt(symbol: Symbol, elf_file: *Elf) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .symbol = symbol,
        .elf_file = elf_file,
    } };
}

fn format2(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const symbol = ctx.symbol;
    try writer.print("%{d} : {s} : @{x}", .{
        symbol.esym_index,
        symbol.fmt_name(ctx.elf_file),
        symbol.address(.{}, ctx.elf_file),
    });
    if (symbol.file(ctx.elf_file)) |file_ptr| {
        if (symbol.is_abs(ctx.elf_file)) {
            if (symbol.elf_sym(ctx.elf_file).st_shndx == elf.SHN_UNDEF) {
                try writer.write_all(" : undef");
            } else {
                try writer.write_all(" : absolute");
            }
        } else if (symbol.output_shndx()) |shndx| {
            try writer.print(" : shdr({d})", .{shndx});
        }
        if (symbol.atom(ctx.elf_file)) |atom_ptr| {
            try writer.print(" : atom({d})", .{atom_ptr.atom_index});
        }
        var buf: [2]u8 = .{'_'} ** 2;
        if (symbol.flags.@"export") buf[0] = 'E';
        if (symbol.flags.import) buf[1] = 'I';
        try writer.print(" : {s}", .{&buf});
        if (symbol.flags.weak) try writer.write_all(" : weak");
        switch (file_ptr) {
            inline else => |x| try writer.print(" : {s}({d})", .{ @tag_name(file_ptr), x.index }),
        }
    } else try writer.write_all(" : unresolved");
}

pub const Flags = packed struct {
    /// Whether the symbol is imported at runtime.
    import: bool = false,

    /// Whether the symbol is exported at runtime.
    @"export": bool = false,

    /// Whether this symbol is weak.
    weak: bool = false,

    /// Whether the symbol has its name interned in global symbol
    /// resolver table.
    /// This happens for any symbol that is considered a global
    /// symbol, but is not necessarily an import or export.
    global: bool = false,

    /// Whether the symbol makes into the output symtab.
    output_symtab: bool = false,

    /// Whether the symbol has entry in dynamic symbol table.
    has_dynamic: bool = false,

    /// Whether the symbol contains GOT indirection.
    needs_got: bool = false,
    has_got: bool = false,

    /// Whether the symbol contains PLT indirection.
    needs_plt: bool = false,
    has_plt: bool = false,
    /// Whether the PLT entry is canonical.
    is_canonical: bool = false,

    /// Whether the symbol contains COPYREL directive.
    needs_copy_rel: bool = false,
    has_copy_rel: bool = false,

    /// Whether the symbol contains TLSGD indirection.
    needs_tlsgd: bool = false,
    has_tlsgd: bool = false,

    /// Whether the symbol contains GOTTP indirection.
    needs_gottp: bool = false,
    has_gottp: bool = false,

    /// Whether the symbol contains TLSDESC indirection.
    needs_tlsdesc: bool = false,
    has_tlsdesc: bool = false,

    /// Whether the symbol contains .zig.got indirection.
    needs_zig_got: bool = false,
    has_zig_got: bool = false,

    /// Whether the symbol is a TLS variable.
    /// TODO this is really not needed if only we operated on esyms between
    /// codegen and ZigObject.
    is_tls: bool = false,

    /// Whether the symbol is a merge subsection.
    merge_subsection: bool = false,
};

pub const Extra = struct {
    got: u32 = 0,
    plt: u32 = 0,
    plt_got: u32 = 0,
    dynamic: u32 = 0,
    symtab: u32 = 0,
    copy_rel: u32 = 0,
    tlsgd: u32 = 0,
    gottp: u32 = 0,
    tlsdesc: u32 = 0,
    zig_got: u32 = 0,
    subsection: u32 = 0,
};

pub const Index = u32;

const assert = std.debug.assert;
const elf = std.elf;
const mem = std.mem;
const std = @import("std");
const synthetic_sections = @import("synthetic_sections.zig");

const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const File = @import("file.zig").File;
const GotSection = synthetic_sections.GotSection;
const GotPltSection = synthetic_sections.GotPltSection;
const LinkerDefined = @import("LinkerDefined.zig");
const MergeSubsection = @import("merge_section.zig").MergeSubsection;
const Object = @import("Object.zig");
const PltSection = synthetic_sections.PltSection;
const PltGotSection = synthetic_sections.PltGotSection;
const SharedObject = @import("SharedObject.zig");
const Symbol = @This();
const ZigGotSection = synthetic_sections.ZigGotSection;
