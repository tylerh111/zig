pub const File = union(enum) {
    zig_object: *ZigObject,
    internal: *InternalObject,
    object: *Object,
    dylib: *Dylib,

    pub fn get_index(file: File) Index {
        return switch (file) {
            inline else => |x| x.index,
        };
    }

    pub fn fmt_path(file: File) std.fmt.Formatter(format_path) {
        return .{ .data = file };
    }

    fn format_path(
        file: File,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        switch (file) {
            .zig_object => |x| try writer.write_all(x.path),
            .internal => try writer.write_all(""),
            .object => |x| try writer.print("{}", .{x.fmt_path()}),
            .dylib => |x| try writer.write_all(x.path),
        }
    }

    pub fn resolve_symbols(file: File, macho_file: *MachO) void {
        switch (file) {
            .internal => unreachable,
            inline else => |x| x.resolve_symbols(macho_file),
        }
    }

    pub fn reset_globals(file: File, macho_file: *MachO) void {
        switch (file) {
            .internal => unreachable,
            inline else => |x| x.reset_globals(macho_file),
        }
    }

    pub fn claim_unresolved(file: File, macho_file: *MachO) error{OutOfMemory}!void {
        assert(file == .object or file == .zig_object);

        for (file.get_symbols(), 0..) |sym_index, i| {
            const nlist_idx = @as(Symbol.Index, @int_cast(i));
            const nlist = switch (file) {
                .object => |x| x.symtab.items(.nlist)[nlist_idx],
                .zig_object => |x| x.symtab.items(.nlist)[nlist_idx],
                else => unreachable,
            };
            if (!nlist.ext()) continue;
            if (!nlist.undf()) continue;

            const sym = macho_file.get_symbol(sym_index);
            if (sym.get_file(macho_file) != null) continue;

            const is_import = switch (macho_file.undefined_treatment) {
                .@"error" => false,
                .warn, .suppress => nlist.weak_ref(),
                .dynamic_lookup => true,
            };
            if (is_import) {
                sym.value = 0;
                sym.atom = 0;
                sym.nlist_idx = 0;
                sym.file = macho_file.internal_object.?;
                sym.flags.weak = false;
                sym.flags.weak_ref = nlist.weak_ref();
                sym.flags.import = is_import;
                sym.visibility = .global;
                try macho_file.get_internal_object().?.symbols.append(macho_file.base.comp.gpa, sym_index);
            }
        }
    }

    pub fn claim_unresolved_relocatable(file: File, macho_file: *MachO) void {
        assert(file == .object or file == .zig_object);

        for (file.get_symbols(), 0..) |sym_index, i| {
            const nlist_idx = @as(Symbol.Index, @int_cast(i));
            const nlist = switch (file) {
                .object => |x| x.symtab.items(.nlist)[nlist_idx],
                .zig_object => |x| x.symtab.items(.nlist)[nlist_idx],
                else => unreachable,
            };
            if (!nlist.ext()) continue;
            if (!nlist.undf()) continue;

            const sym = macho_file.get_symbol(sym_index);
            if (sym.get_file(macho_file) != null) continue;

            sym.value = 0;
            sym.atom = 0;
            sym.nlist_idx = nlist_idx;
            sym.file = file.get_index();
            sym.flags.weak_ref = nlist.weak_ref();
            sym.flags.import = true;
            sym.visibility = .global;
        }
    }

    pub fn mark_imports_exports(file: File, macho_file: *MachO) void {
        assert(file == .object or file == .zig_object);

        for (file.get_symbols()) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            const other_file = sym.get_file(macho_file) orelse continue;
            if (sym.visibility != .global) continue;
            if (other_file == .dylib and !sym.flags.abs) {
                sym.flags.import = true;
                continue;
            }
            if (other_file.get_index() == file.get_index()) {
                sym.flags.@"export" = true;
            }
        }
    }

    pub fn mark_exports_relocatable(file: File, macho_file: *MachO) void {
        assert(file == .object or file == .zig_object);

        for (file.get_symbols()) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            const other_file = sym.get_file(macho_file) orelse continue;
            if (sym.visibility != .global) continue;
            if (other_file.get_index() == file.get_index()) {
                sym.flags.@"export" = true;
            }
        }
    }

    /// Encodes symbol rank so that the following ordering applies:
    /// * strong in object
    /// * weak in object
    /// * tentative in object
    /// * strong in archive/dylib
    /// * weak in archive/dylib
    /// * tentative in archive
    /// * unclaimed
    pub fn get_symbol_rank(file: File, args: struct {
        archive: bool = false,
        weak: bool = false,
        tentative: bool = false,
    }) u32 {
        if (file == .object and !args.archive) {
            const base: u32 = blk: {
                if (args.tentative) break :blk 3;
                break :blk if (args.weak) 2 else 1;
            };
            return (base << 16) + file.get_index();
        }
        const base: u32 = blk: {
            if (args.tentative) break :blk 3;
            break :blk if (args.weak) 2 else 1;
        };
        return base + (file.get_index() << 24);
    }

    pub fn get_symbols(file: File) []const Symbol.Index {
        return switch (file) {
            inline else => |x| x.symbols.items,
        };
    }

    pub fn get_atoms(file: File) []const Atom.Index {
        return switch (file) {
            .dylib => unreachable,
            inline else => |x| x.atoms.items,
        };
    }

    pub fn update_ar_symtab(file: File, ar_symtab: *Archive.ArSymtab, macho_file: *MachO) error{OutOfMemory}!void {
        return switch (file) {
            .dylib, .internal => unreachable,
            inline else => |x| x.update_ar_symtab(ar_symtab, macho_file),
        };
    }

    pub fn update_ar_size(file: File, macho_file: *MachO) !void {
        return switch (file) {
            .dylib, .internal => unreachable,
            .zig_object => |x| x.update_ar_size(),
            .object => |x| x.update_ar_size(macho_file),
        };
    }

    pub fn write_ar(file: File, ar_format: Archive.Format, macho_file: *MachO, writer: anytype) !void {
        return switch (file) {
            .dylib, .internal => unreachable,
            .zig_object => |x| x.write_ar(ar_format, writer),
            .object => |x| x.write_ar(ar_format, macho_file, writer),
        };
    }

    pub fn calc_symtab_size(file: File, macho_file: *MachO) !void {
        return switch (file) {
            inline else => |x| x.calc_symtab_size(macho_file),
        };
    }

    pub fn write_symtab(file: File, macho_file: *MachO, ctx: anytype) !void {
        return switch (file) {
            inline else => |x| x.write_symtab(macho_file, ctx),
        };
    }

    pub const Index = u32;

    pub const Entry = union(enum) {
        null: void,
        zig_object: ZigObject,
        internal: InternalObject,
        object: Object,
        dylib: Dylib,
    };

    pub const Handle = std.fs.File;
    pub const HandleIndex = Index;
};

const assert = std.debug.assert;
const macho = std.macho;
const std = @import("std");

const Allocator = std.mem.Allocator;
const Archive = @import("Archive.zig");
const Atom = @import("Atom.zig");
const InternalObject = @import("InternalObject.zig");
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Dylib = @import("Dylib.zig");
const Symbol = @import("Symbol.zig");
const ZigObject = @import("ZigObject.zig");
