//! Represents a defined symbol.

/// Allocated address value of this symbol.
value: u64 = 0,

/// Offset into the linker's intern table.
name: u32 = 0,

/// File where this symbol is defined.
file: File.Index = 0,

/// Atom containing this symbol if any.
/// Index of 0 means there is no associated atom with this symbol.
/// Use `get_atom` to get the pointer to the atom.
atom: Atom.Index = 0,

/// Assigned output section index for this symbol.
out_n_sect: u8 = 0,

/// Index of the source nlist this symbol references.
/// Use `get_nlist` to pull the nlist from the relevant file.
nlist_idx: Index = 0,

/// Misc flags for the symbol packaged as packed struct for compression.
flags: Flags = .{},

visibility: Visibility = .local,

extra: u32 = 0,

pub fn is_local(symbol: Symbol) bool {
    return !(symbol.flags.import or symbol.flags.@"export");
}

pub fn is_symbol_stab(symbol: Symbol, macho_file: *MachO) bool {
    const file = symbol.get_file(macho_file) orelse return false;
    return switch (file) {
        .object => symbol.get_nlist(macho_file).stab(),
        else => false,
    };
}

pub fn is_tlv_init(symbol: Symbol, macho_file: *MachO) bool {
    const name = symbol.get_name(macho_file);
    return std.mem.index_of(u8, name, "$tlv$init") != null;
}

pub fn weak_ref(symbol: Symbol, macho_file: *MachO) bool {
    const file = symbol.get_file(macho_file).?;
    const is_dylib_weak = switch (file) {
        .dylib => |x| x.weak,
        else => false,
    };
    return is_dylib_weak or symbol.flags.weak_ref;
}

pub fn get_name(symbol: Symbol, macho_file: *MachO) [:0]const u8 {
    if (symbol.flags.global) return macho_file.strings.get_assume_exists(symbol.name);
    return switch (symbol.get_file(macho_file).?) {
        .dylib => unreachable, // There are no local symbols for dylibs
        .zig_object => |x| x.strtab.get_assume_exists(symbol.name),
        inline else => |x| x.get_string(symbol.name),
    };
}

pub fn get_atom(symbol: Symbol, macho_file: *MachO) ?*Atom {
    return macho_file.get_atom(symbol.atom);
}

pub fn get_file(symbol: Symbol, macho_file: *MachO) ?File {
    return macho_file.get_file(symbol.file);
}

/// Asserts file is an object.
pub fn get_nlist(symbol: Symbol, macho_file: *MachO) macho.nlist_64 {
    const file = symbol.get_file(macho_file).?;
    return switch (file) {
        .object => |x| x.symtab.items(.nlist)[symbol.nlist_idx],
        else => unreachable,
    };
}

pub fn get_size(symbol: Symbol, macho_file: *MachO) u64 {
    const file = symbol.get_file(macho_file).?;
    assert(file == .object);
    return file.object.symtab.items(.size)[symbol.nlist_idx];
}

pub fn get_dylib_ordinal(symbol: Symbol, macho_file: *MachO) ?u16 {
    assert(symbol.flags.import);
    const file = symbol.get_file(macho_file) orelse return null;
    return switch (file) {
        .dylib => |x| x.ordinal,
        else => null,
    };
}

pub fn get_symbol_rank(symbol: Symbol, macho_file: *MachO) u32 {
    const file = symbol.get_file(macho_file) orelse return std.math.max_int(u32);
    const in_archive = switch (file) {
        .object => |x| !x.alive,
        else => false,
    };
    return file.get_symbol_rank(.{
        .archive = in_archive,
        .weak = symbol.flags.weak,
        .tentative = symbol.flags.tentative,
    });
}

pub fn get_address(symbol: Symbol, opts: struct {
    stubs: bool = true,
}, macho_file: *MachO) u64 {
    if (opts.stubs) {
        if (symbol.flags.stubs) {
            return symbol.get_stubs_address(macho_file);
        } else if (symbol.flags.objc_stubs) {
            return symbol.get_objc_stubs_address(macho_file);
        }
    }
    if (symbol.get_atom(macho_file)) |atom| return atom.get_address(macho_file) + symbol.value;
    return symbol.value;
}

pub fn get_got_address(symbol: Symbol, macho_file: *MachO) u64 {
    if (!symbol.flags.has_got) return 0;
    const extra = symbol.get_extra(macho_file).?;
    return macho_file.got.get_address(extra.got, macho_file);
}

pub fn get_stubs_address(symbol: Symbol, macho_file: *MachO) u64 {
    if (!symbol.flags.stubs) return 0;
    const extra = symbol.get_extra(macho_file).?;
    return macho_file.stubs.get_address(extra.stubs, macho_file);
}

pub fn get_objc_stubs_address(symbol: Symbol, macho_file: *MachO) u64 {
    if (!symbol.flags.objc_stubs) return 0;
    const extra = symbol.get_extra(macho_file).?;
    return macho_file.objc_stubs.get_address(extra.objc_stubs, macho_file);
}

pub fn get_objc_selrefs_address(symbol: Symbol, macho_file: *MachO) u64 {
    if (!symbol.flags.objc_stubs) return 0;
    const extra = symbol.get_extra(macho_file).?;
    const atom = macho_file.get_atom(extra.objc_selrefs).?;
    assert(atom.flags.alive);
    return atom.get_address(macho_file);
}

pub fn get_tlv_ptr_address(symbol: Symbol, macho_file: *MachO) u64 {
    if (!symbol.flags.tlv_ptr) return 0;
    const extra = symbol.get_extra(macho_file).?;
    return macho_file.tlv_ptr.get_address(extra.tlv_ptr, macho_file);
}

const GetOrCreateZigGotEntryResult = struct {
    found_existing: bool,
    index: ZigGotSection.Index,
};

pub fn get_or_create_zig_got_entry(symbol: *Symbol, symbol_index: Index, macho_file: *MachO) !GetOrCreateZigGotEntryResult {
    assert(!macho_file.base.is_relocatable());
    assert(symbol.flags.needs_zig_got);
    if (symbol.flags.has_zig_got) return .{ .found_existing = true, .index = symbol.get_extra(macho_file).?.zig_got };
    const index = try macho_file.zig_got.add_symbol(symbol_index, macho_file);
    return .{ .found_existing = false, .index = index };
}

pub fn get_zig_got_address(symbol: Symbol, macho_file: *MachO) u64 {
    if (!symbol.flags.has_zig_got) return 0;
    const extras = symbol.get_extra(macho_file).?;
    return macho_file.zig_got.entry_address(extras.zig_got, macho_file);
}

pub fn get_output_symtab_index(symbol: Symbol, macho_file: *MachO) ?u32 {
    if (!symbol.flags.output_symtab) return null;
    assert(!symbol.is_symbol_stab(macho_file));
    const file = symbol.get_file(macho_file).?;
    const symtab_ctx = switch (file) {
        inline else => |x| x.output_symtab_ctx,
    };
    var idx = symbol.get_extra(macho_file).?.symtab;
    if (symbol.is_local()) {
        idx += symtab_ctx.ilocal;
    } else if (symbol.flags.@"export") {
        idx += symtab_ctx.iexport;
    } else {
        assert(symbol.flags.import);
        idx += symtab_ctx.iimport;
    }
    return idx;
}

const AddExtraOpts = struct {
    got: ?u32 = null,
    zig_got: ?u32 = null,
    stubs: ?u32 = null,
    objc_stubs: ?u32 = null,
    objc_selrefs: ?u32 = null,
    tlv_ptr: ?u32 = null,
    symtab: ?u32 = null,
};

pub fn add_extra(symbol: *Symbol, opts: AddExtraOpts, macho_file: *MachO) !void {
    if (symbol.get_extra(macho_file) == null) {
        symbol.extra = try macho_file.add_symbol_extra(.{});
    }
    var extra = symbol.get_extra(macho_file).?;
    inline for (@typeInfo(@TypeOf(opts)).Struct.fields) |field| {
        if (@field(opts, field.name)) |x| {
            @field(extra, field.name) = x;
        }
    }
    symbol.set_extra(extra, macho_file);
}

pub inline fn get_extra(symbol: Symbol, macho_file: *MachO) ?Extra {
    return macho_file.get_symbol_extra(symbol.extra);
}

pub inline fn set_extra(symbol: Symbol, extra: Extra, macho_file: *MachO) void {
    macho_file.set_symbol_extra(symbol.extra, extra);
}

pub fn set_output_sym(symbol: Symbol, macho_file: *MachO, out: *macho.nlist_64) void {
    if (symbol.is_local()) {
        out.n_type = if (symbol.flags.abs) macho.N_ABS else macho.N_SECT;
        out.n_sect = if (symbol.flags.abs) 0 else @int_cast(symbol.out_n_sect + 1);
        out.n_desc = 0;
        out.n_value = symbol.get_address(.{ .stubs = false }, macho_file);

        switch (symbol.visibility) {
            .hidden => out.n_type |= macho.N_PEXT,
            else => {},
        }
    } else if (symbol.flags.@"export") {
        assert(symbol.visibility == .global);
        out.n_type = macho.N_EXT;
        out.n_type |= if (symbol.flags.abs) macho.N_ABS else macho.N_SECT;
        out.n_sect = if (symbol.flags.abs) 0 else @int_cast(symbol.out_n_sect + 1);
        out.n_value = symbol.get_address(.{ .stubs = false }, macho_file);
        out.n_desc = 0;

        if (symbol.flags.weak) {
            out.n_desc |= macho.N_WEAK_DEF;
        }
        if (symbol.flags.dyn_ref) {
            out.n_desc |= macho.REFERENCED_DYNAMICALLY;
        }
    } else {
        assert(symbol.visibility == .global);
        out.n_type = macho.N_EXT;
        out.n_sect = 0;
        out.n_value = 0;
        out.n_desc = 0;

        // TODO:
        // const ord: u16 = if (macho_file.options.namespace == .flat)
        //     @as(u8, @bit_cast(macho.BIND_SPECIAL_DYLIB_FLAT_LOOKUP))
        // else if (symbol.get_dylib_ordinal(macho_file)) |ord|
        //     ord
        // else
        //     macho.BIND_SPECIAL_DYLIB_SELF;
        const ord: u16 = if (symbol.get_dylib_ordinal(macho_file)) |ord|
            ord
        else
            macho.BIND_SPECIAL_DYLIB_SELF;
        out.n_desc = macho.N_SYMBOL_RESOLVER * ord;

        if (symbol.flags.weak) {
            out.n_desc |= macho.N_WEAK_DEF;
        }

        if (symbol.weak_ref(macho_file)) {
            out.n_desc |= macho.N_WEAK_REF;
        }
    }
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
    macho_file: *MachO,
};

pub fn fmt(symbol: Symbol, macho_file: *MachO) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .symbol = symbol,
        .macho_file = macho_file,
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
        symbol.nlist_idx,
        symbol.get_name(ctx.macho_file),
        symbol.get_address(.{}, ctx.macho_file),
    });
    if (symbol.get_file(ctx.macho_file)) |file| {
        if (symbol.out_n_sect != 0) {
            try writer.print(" : sect({d})", .{symbol.out_n_sect});
        }
        if (symbol.get_atom(ctx.macho_file)) |atom| {
            try writer.print(" : atom({d})", .{atom.atom_index});
        }
        var buf: [2]u8 = .{'_'} ** 2;
        if (symbol.flags.@"export") buf[0] = 'E';
        if (symbol.flags.import) buf[1] = 'I';
        try writer.print(" : {s}", .{&buf});
        if (symbol.flags.weak) try writer.write_all(" : weak");
        if (symbol.is_symbol_stab(ctx.macho_file)) try writer.write_all(" : stab");
        switch (file) {
            .zig_object => |x| try writer.print(" : zig_object({d})", .{x.index}),
            .internal => |x| try writer.print(" : internal({d})", .{x.index}),
            .object => |x| try writer.print(" : object({d})", .{x.index}),
            .dylib => |x| try writer.print(" : dylib({d})", .{x.index}),
        }
    } else try writer.write_all(" : unresolved");
}

pub const Flags = packed struct {
    /// Whether the symbol is imported at runtime.
    import: bool = false,

    /// Whether the symbol is exported at runtime.
    @"export": bool = false,

    /// Whether the symbol is effectively an extern and takes part in global
    /// symbol resolution. Then, its name will be saved in global string interning
    /// table.
    global: bool = false,

    /// Whether this symbol is weak.
    weak: bool = false,

    /// Whether this symbol is weakly referenced.
    weak_ref: bool = false,

    /// Whether this symbol is dynamically referenced.
    dyn_ref: bool = false,

    /// Whether this symbol was marked as N_NO_DEAD_STRIP.
    no_dead_strip: bool = false,

    /// Whether this symbol can be interposed at runtime.
    interposable: bool = false,

    /// Whether this symbol is absolute.
    abs: bool = false,

    /// Whether this symbol is a tentative definition.
    tentative: bool = false,

    /// Whether this symbol is a thread-local variable.
    tlv: bool = false,

    /// Whether the symbol makes into the output symtab or not.
    output_symtab: bool = false,

    /// Whether the symbol contains __got indirection.
    needs_got: bool = false,
    has_got: bool = false,

    /// Whether the symbol contains __got_zig indirection.
    needs_zig_got: bool = false,
    has_zig_got: bool = false,

    /// Whether the symbols contains __stubs indirection.
    stubs: bool = false,

    /// Whether the symbol has a TLV pointer.
    tlv_ptr: bool = false,

    /// Whether the symbol contains __objc_stubs indirection.
    objc_stubs: bool = false,
};

pub const Visibility = enum {
    global,
    hidden,
    local,
};

pub const Extra = struct {
    got: u32 = 0,
    zig_got: u32 = 0,
    stubs: u32 = 0,
    objc_stubs: u32 = 0,
    objc_selrefs: u32 = 0,
    tlv_ptr: u32 = 0,
    symtab: u32 = 0,
};

pub const Index = u32;

const assert = std.debug.assert;
const macho = std.macho;
const std = @import("std");

const Atom = @import("Atom.zig");
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Nlist = Object.Nlist;
const Object = @import("Object.zig");
const Symbol = @This();
const ZigGotSection = @import("synthetic.zig").ZigGotSection;
