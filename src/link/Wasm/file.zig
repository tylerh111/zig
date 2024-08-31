pub const File = union(enum) {
    zig_object: *ZigObject,
    object: *Object,

    pub const Index = enum(u16) {
        null = std.math.max_int(u16),
        _,
    };

    pub fn path(file: File) []const u8 {
        return switch (file) {
            inline else => |obj| obj.path,
        };
    }

    pub fn segment_info(file: File) []const types.Segment {
        return switch (file) {
            .zig_object => |obj| obj.segment_info.items,
            .object => |obj| obj.segment_info,
        };
    }

    pub fn symbol(file: File, index: Symbol.Index) *Symbol {
        return switch (file) {
            .zig_object => |obj| &obj.symbols.items[@int_from_enum(index)],
            .object => |obj| &obj.symtable[@int_from_enum(index)],
        };
    }

    pub fn symbols(file: File) []const Symbol {
        return switch (file) {
            .zig_object => |obj| obj.symbols.items,
            .object => |obj| obj.symtable,
        };
    }

    pub fn symbol_name(file: File, index: Symbol.Index) []const u8 {
        switch (file) {
            .zig_object => |obj| {
                const sym = obj.symbols.items[@int_from_enum(index)];
                return obj.string_table.get(sym.name).?;
            },
            .object => |obj| {
                const sym = obj.symtable[@int_from_enum(index)];
                return obj.string_table.get(sym.name);
            },
        }
    }

    pub fn parse_symbol_into_atom(file: File, wasm_file: *Wasm, index: Symbol.Index) !AtomIndex {
        return switch (file) {
            inline else => |obj| obj.parse_symbol_into_atom(wasm_file, index),
        };
    }

    /// For a given symbol index, find its corresponding import.
    /// Asserts import exists.
    pub fn import(file: File, symbol_index: Symbol.Index) types.Import {
        return switch (file) {
            .zig_object => |obj| obj.imports.get(symbol_index).?,
            .object => |obj| obj.find_import(obj.symtable[@int_from_enum(symbol_index)]),
        };
    }

    /// For a given offset, returns its string value.
    /// Asserts string exists in the object string table.
    pub fn string(file: File, offset: u32) []const u8 {
        return switch (file) {
            .zig_object => |obj| obj.string_table.get(offset).?,
            .object => |obj| obj.string_table.get(offset),
        };
    }

    pub fn imported_globals(file: File) u32 {
        return switch (file) {
            inline else => |obj| obj.imported_globals_count,
        };
    }

    pub fn imported_functions(file: File) u32 {
        return switch (file) {
            inline else => |obj| obj.imported_functions_count,
        };
    }

    pub fn imported_tables(file: File) u32 {
        return switch (file) {
            inline else => |obj| obj.imported_tables_count,
        };
    }

    pub fn function(file: File, sym_index: Symbol.Index) std.wasm.Func {
        switch (file) {
            .zig_object => |obj| {
                const sym = obj.symbols.items[@int_from_enum(sym_index)];
                return obj.functions.items[sym.index];
            },
            .object => |obj| {
                const sym = obj.symtable[@int_from_enum(sym_index)];
                return obj.functions[sym.index - obj.imported_functions_count];
            },
        }
    }

    pub fn globals(file: File) []const std.wasm.Global {
        return switch (file) {
            .zig_object => |obj| obj.globals.items,
            .object => |obj| obj.globals,
        };
    }

    pub fn func_types(file: File) []const std.wasm.Type {
        return switch (file) {
            .zig_object => |obj| obj.func_types.items,
            .object => |obj| obj.func_types,
        };
    }

    pub const Entry = union(enum) {
        zig_object: ZigObject,
        object: Object,
    };
};

const std = @import("std");
const types = @import("types.zig");

const AtomIndex = @import("Atom.zig").Index;
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
const Wasm = @import("../Wasm.zig");
const ZigObject = @import("ZigObject.zig");
